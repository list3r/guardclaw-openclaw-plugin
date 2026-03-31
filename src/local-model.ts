/**
 * GuardClaw Local Model Detector
 *
 * Provider-agnostic edge model integration supporting multiple API protocols:
 *   - "openai-compatible": /v1/chat/completions (Ollama, vLLM, LiteLLM, LocalAI, LMStudio, SGLang, TGI …)
 *   - "ollama-native":     /api/chat (Ollama native API)
 *   - "custom":            User-supplied module with callChat() export
 */

import type {
  DetectionContext,
  DetectionResult,
  EdgeProviderType,
  PrivacyConfig,
  SensitivityLevel,
} from "./types.js";
import { loadPrompt, loadPromptWithVars } from "./prompt-loader.js";
import { buildFewShotExamples, loadCorrections, getAuthoritativeOverride } from "./correction-store.js";
import { levelToNumeric } from "./types.js";
import { getGlobalCollector } from "./token-stats.js";
import { recordRouterOperation } from "./usage-intel.js";

export type ChatMessage = { role: "system" | "user" | "assistant"; content: string };

export type ChatCompletionOptions = {
  temperature?: number;
  maxTokens?: number;
  stop?: string[];
  frequencyPenalty?: number;
  apiKey?: string;
  /** Force-disable reasoning output for compatible backends. */
  disableThinking?: boolean;
};

export type LlmUsageInfo = {
  input: number;
  output: number;
  total: number;
};

export type ChatCompletionResult = {
  text: string;
  usage?: LlmUsageInfo;
};

/**
 * Custom edge provider module interface.
 * Users implementing type="custom" must export a module matching this shape.
 */
export interface CustomEdgeProvider {
  callChat(
    endpoint: string,
    model: string,
    messages: ChatMessage[],
    options?: ChatCompletionOptions,
  ): Promise<string>;
}

const _customProviderCache: Map<string, CustomEdgeProvider> = new Map();

async function loadCustomProvider(modulePath: string): Promise<CustomEdgeProvider> {
  const cached = _customProviderCache.get(modulePath);
  if (cached) return cached;
  const mod = await import(modulePath) as CustomEdgeProvider;
  if (typeof mod.callChat !== "function") {
    throw new Error(`Custom edge provider at "${modulePath}" must export a callChat() function`);
  }
  _customProviderCache.set(modulePath, mod);
  return mod;
}

/**
 * Dispatch a chat completion call based on the configured edge provider type.
 * This is the single entry point for all edge model calls.
 *
 * Returns a ChatCompletionResult with the response text and optional usage info
 * parsed from the API response (for token accounting).
 */
export async function callChatCompletion(
  endpoint: string,
  model: string,
  messages: ChatMessage[],
  options?: ChatCompletionOptions & { providerType?: EdgeProviderType; customModule?: string },
): Promise<ChatCompletionResult> {
  const providerType = options?.providerType ?? "openai-compatible";

  let result: ChatCompletionResult;
  switch (providerType) {
    case "ollama-native":
      result = await callOllamaNative(endpoint, model, messages, options);
      break;
    case "custom": {
      if (!options?.customModule) {
        throw new Error("Custom edge provider requires a 'module' path in localModel config");
      }
      const provider = await loadCustomProvider(options.customModule);
      const text = await provider.callChat(endpoint, model, messages, options);
      result = { text };
      break;
    }
    case "openai-compatible":
    default:
      result = await callOpenAICompatible(endpoint, model, messages, options);
      break;
  }
  return result;
}

/**
 * OpenAI-compatible chat completions call.
 * POST ${endpoint}/v1/chat/completions — works with Ollama, vLLM, LiteLLM, LocalAI, LMStudio, SGLang, TGI, etc.
 */
const GUARDCLAW_FETCH_TIMEOUT_MS = 60_000;

async function callOpenAICompatible(
  endpoint: string,
  model: string,
  messages: ChatMessage[],
  options?: ChatCompletionOptions,
): Promise<ChatCompletionResult> {
  const url = `${endpoint}/v1/chat/completions`;

  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (options?.apiKey) {
    headers["Authorization"] = `Bearer ${options.apiKey}`;
  }

  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({
      model,
      messages,
      temperature: options?.temperature ?? 0.1,
      max_tokens: options?.maxTokens ?? 800,
      stream: true,
      ...(options?.stop ? { stop: options.stop } : {}),
      ...(options?.frequencyPenalty != null ? { frequency_penalty: options.frequencyPenalty } : {}),
      ...(options?.disableThinking
        ? { chat_template_kwargs: { enable_thinking: false } }
        : {}),
    }),
    signal: AbortSignal.timeout(GUARDCLAW_FETCH_TIMEOUT_MS),
  });

  if (!response.ok) {
    throw new Error(`Chat completions API error: ${response.status} ${response.statusText}`);
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("text/event-stream") && response.body) {
    return await consumeSSEStream(response.body);
  }

  const data = (await response.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
    usage?: { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number };
  };
  let text = data.choices?.[0]?.message?.content ?? "";
  text = stripThinkingTags(text);

  const usage: LlmUsageInfo | undefined = data.usage
    ? {
        input: data.usage.prompt_tokens ?? 0,
        output: data.usage.completion_tokens ?? 0,
        total: data.usage.total_tokens ?? (data.usage.prompt_tokens ?? 0) + (data.usage.completion_tokens ?? 0),
      }
    : undefined;

  return { text, usage };
}

async function consumeSSEStream(
  body: ReadableStream<Uint8Array>,
): Promise<ChatCompletionResult> {
  const decoder = new TextDecoder();
  const reader = body.getReader();
  let textParts: string[] = [];
  let usage: LlmUsageInfo | undefined;
  let buffer = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("data:")) continue;
        const payload = trimmed.slice(5).trim();
        if (payload === "[DONE]") continue;

        try {
          const chunk = JSON.parse(payload) as {
            choices?: Array<{ delta?: { content?: string; reasoning_content?: string } }>;
            usage?: { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number };
          };
          const delta = chunk.choices?.[0]?.delta;
          if (delta?.content) {
            textParts.push(delta.content);
          }
          if (chunk.usage) {
            usage = {
              input: chunk.usage.prompt_tokens ?? 0,
              output: chunk.usage.completion_tokens ?? 0,
              total: chunk.usage.total_tokens ?? 0,
            };
          }
        } catch {
          // skip malformed SSE chunks
        }
      }
    }
  } finally {
    reader.releaseLock();
  }

  let text = textParts.join("");
  text = stripThinkingTags(text);
  return { text, usage };
}

/**
 * Ollama native API call.
 * POST ${endpoint}/api/chat — Ollama's own protocol (non-streaming).
 */
async function callOllamaNative(
  endpoint: string,
  model: string,
  messages: ChatMessage[],
  options?: ChatCompletionOptions,
): Promise<ChatCompletionResult> {
  const url = `${endpoint}/api/chat`;

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      messages,
      stream: false,
      options: {
        temperature: options?.temperature ?? 0.1,
        num_predict: options?.maxTokens ?? 800,
        ...(options?.stop ? { stop: options.stop } : {}),
        ...(options?.frequencyPenalty != null ? { repeat_penalty: 1.0 + (options.frequencyPenalty ?? 0) } : {}),
      },
    }),
  });

  if (!response.ok) {
    throw new Error(`Ollama native API error: ${response.status} ${response.statusText}`);
  }

  const data = (await response.json()) as {
    message?: { content?: string };
    prompt_eval_count?: number;
    eval_count?: number;
  };
  let text = data.message?.content ?? "";
  text = stripThinkingTags(text);

  const promptTokens = data.prompt_eval_count ?? 0;
  const outputTokens = data.eval_count ?? 0;
  const usage: LlmUsageInfo | undefined = (promptTokens || outputTokens)
    ? { input: promptTokens, output: outputTokens, total: promptTokens + outputTokens }
    : undefined;

  return { text, usage };
}

/** Strip <think>...</think> blocks emitted by reasoning models (MiniCPM, Qwen3, etc.) */
function stripThinkingTags(text: string): string {
  let result = text.replace(/<think>[\s\S]*?<\/think>/g, "").trim();
  const lastThinkClose = result.lastIndexOf("</think>");
  if (lastThinkClose !== -1) {
    result = result.slice(lastThinkClose + "</think>".length).trim();
  }
  return result;
}

/**
 * Detect sensitivity level using a local model
 */
export async function detectByLocalModel(
  context: DetectionContext,
  config: PrivacyConfig,
): Promise<DetectionResult> {
  // Check if local model is enabled
  if (!config.localModel?.enabled) {
    return {
      level: "S1",
      levelNumeric: 1,
      reason: "Local model detection disabled",
      detectorType: "localModelDetector",
      confidence: 0,
    };
  }

  try {
    const { system, user } = await buildDetectionMessages(context);
    const result = await callLocalModel(system, user, config);
    const parsed = parseModelResponse(result.text);

    if (result.usage) {
      const collector = getGlobalCollector();
      collector?.record({
        sessionKey: context.sessionKey ?? "",
        provider: "edge",
        model: config.localModel?.model ?? "unknown",
        source: "router",
        usage: result.usage,
      });
      recordRouterOperation(
        context.sessionKey,
        "detection",
        result.usage,
        config.localModel?.model ?? "unknown",
        config.localModel?.provider,
      );
    }

    // Check for authoritative correction override (similarity > 0.7)
    const messageText = context.message ?? context.toolName ?? "";
    let finalLevel = parsed.level;
    let finalReason = parsed.reason;
    let finalConfidence = parsed.confidence ?? 0.8;

    try {
      const override = await getAuthoritativeOverride(messageText);
      if (override && override.level !== parsed.level) {
        console.log(
          `[GuardClaw] Correction override: model=${parsed.level} → correction=${override.level} ` +
          `(${override.similarity.toFixed(2)} similarity, id=${override.correctionId})`,
        );
        finalLevel = override.level;
        finalReason = override.reason;
        finalConfidence = Math.min(0.95, override.similarity);
      }
    } catch {
      // Override lookup failed — use model result as-is
    }

    return {
      level: finalLevel,
      levelNumeric: levelToNumeric(finalLevel),
      reason: finalReason,
      detectorType: "localModelDetector",
      confidence: finalConfidence,
    };
  } catch (err) {
    // If local model fails, return S1 (safe) but log the error
    console.error("[GuardClaw] Local model detection failed:", err);
    return {
      level: "S1",
      levelNumeric: 1,
      reason: `Local model error: ${String(err)}`,
      detectorType: "localModelDetector",
      confidence: 0,
    };
  }
}

/** Default detection system prompt (fallback if prompts/detection-system.md is missing) */
export const DEFAULT_DETECTION_SYSTEM_PROMPT = `[SYSTEM] You are a strict privacy classifier. Output ONLY a single JSON object — nothing else.

Classify by BOTH actual data AND intent. If the user asks to read/analyze a file, classify based on what the file WILL contain.

S3 = PRIVATE (local only, never cloud):
  - Financial: payslip, salary, tax, bank account, SSN, 工资单, 报销单, 税表
  - Medical: health records, diagnoses, prescriptions, lab results, 病历, 体检报告
  - Credentials: passwords, API keys, secrets, tokens, private keys
  - ANY request to read/analyze a file about the above topics → S3
  "evaluate these passwords" → S3
  "check my payslip" → S3
  "summarize the medical record" → S3

S2 = SENSITIVE (redact PII, then send to cloud):
  - Addresses (ANY physical address, 地址, 住址, street, road, apartment, 路, 街, 小区, 弄, 号)
  - Gate/door codes, pickup codes, delivery tracking numbers
  - Phone numbers, email addresses, real names used as contact PII
  - License plates, SSN/ID mixed with personal context, chat logs with PII
  - File content containing the above PII → S2
  - ANY mention of "address"/"地址" with actual location data → S2
  "1847 Elm St, gate code 4523#" → S2
  "我的地址是北京市朝阳区xxx" → S2
  "张伟 手机13912345678" → S2
  "my address is 123 Main St" → S2

S1 = SAFE: No sensitive data or intent.
  "write a poem about spring" → S1
  "how to read Excel with pandas" → S1

Rules:
- Passwords/credentials → ALWAYS S3 (never S2)
- Medical data → ALWAYS S3 (never S2)
- Gate/access/pickup codes → S2 (not S3)
- If file content is provided and contains PII → at least S2
- When unsure → pick higher level

Output format: {"level":"S1|S2|S3","reason":"brief"}`;

/**
 * Build separate system/user messages for the detection prompt.
 *
 * System instruction is loaded from prompts/detection-system.md (editable by users).
 * The dynamic [CONTENT] block becomes the user message.
 *
 * When corrections exist, similar past corrections are retrieved via embedding
 * similarity and injected as few-shot examples before the [CONTENT] block.
 */
async function buildDetectionMessages(context: DetectionContext): Promise<{ system: string; user: string }> {
  const system = loadPrompt("detection-system", DEFAULT_DETECTION_SYSTEM_PROMPT);

  // Build the content block
  const contentParts: string[] = ["[CONTENT]"];

  if (context.message) {
    contentParts.push(`Message: ${context.message.slice(0, 1500)}`);
  }

  if (context.toolName) {
    contentParts.push(`Tool: ${context.toolName}`);
  }

  if (context.toolParams) {
    const paramsStr = JSON.stringify(context.toolParams, null, 2);
    contentParts.push(`Tool Parameters: ${paramsStr.slice(0, 800)}`);
  }

  if (context.toolResult) {
    const resultStr =
      typeof context.toolResult === "string"
        ? context.toolResult
        : JSON.stringify(context.toolResult);
    contentParts.push(`Tool Result: ${resultStr.slice(0, 800)}`);
  }

  if (context.recentContext && context.recentContext.length > 0) {
    contentParts.push(`Recent Context: ${context.recentContext.slice(-3).join(" | ")}`);
  }

  contentParts.push("[/CONTENT]");

  // Retrieve similar corrections as few-shot examples (non-blocking on failure)
  const messageText = context.message ?? context.toolName ?? "";
  let fewShotPrefix = "";
  try {
    fewShotPrefix = await buildFewShotExamples(messageText);
  } catch {
    // Embedding service unavailable — proceed without few-shot examples
  }

  return { system, user: fewShotPrefix + contentParts.join("\n") };
}

/**
 * Call local/edge model via the configured provider protocol.
 * Dispatches to the correct API based on localModel.type.
 * Returns both the text response and optional usage info for router overhead tracking.
 */
async function callLocalModel(
  systemPrompt: string,
  userContent: string,
  config: PrivacyConfig,
): Promise<ChatCompletionResult> {
  const model = config.localModel?.model ?? "openbmb/minicpm4.1";
  const endpoint = config.localModel?.endpoint ?? "http://localhost:11434";
  const providerType = config.localModel?.type ?? "openai-compatible";

  return await callChatCompletion(
    endpoint,
    model,
    [
      { role: "system", content: systemPrompt },
      { role: "user", content: userContent },
    ],
    {
      temperature: 0.1,
      maxTokens: 300,
      stop: ["\n\n", "\nExplanation", "\nNote"],
      apiKey: config.localModel?.apiKey,
      disableThinking: true,
      providerType,
      customModule: config.localModel?.module,
    },
  );
}

/**
 * Deterministic regex pre-pass for high-confidence credential patterns.
 * Runs BEFORE the LLM to catch patterns the model misses in unusual phrasings.
 *
 * Strategy: conservative — only replace things we're sure are secrets.
 * False negatives (missed secrets) are worse than false positives (over-redaction).
 */
export function preRedactCredentials(content: string): string {
  let out = content;

  // AWS access keys (AKIA/ASIA prefix, 20 chars alphanumeric)
  // Catches: bare keys, export KEY=AKIA..., "key is AKIA...", key=AKIA...
  out = out.replace(/\bAKIA[A-Z0-9]{16}\b/g, "[REDACTED:CREDENTIAL]");
  out = out.replace(/\bASIA[A-Z0-9]{16}\b/g, "[REDACTED:CREDENTIAL]");

  // AWS secret access key (40-char base64-ish after label)
  out = out.replace(/(aws_secret_access_key\s*[=:]\s*)\S+/gi, "$1[REDACTED:CREDENTIAL]");
  out = out.replace(/(AWS_SECRET_ACCESS_KEY\s*[=:]\s*)\S+/gi, "$1[REDACTED:CREDENTIAL]");

  // Redis URL: redis://:password@host or redis://user:password@host
  out = out.replace(/redis:\/\/[^@\s]*:[^@\s]+@/gi, "redis://[REDACTED:CREDENTIAL]@");

  // Generic URL credentials: proto://user:pass@host
  out = out.replace(/((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|amqp|smtp|ftp|ftps):\/\/[^:\s]*:)[^@\s]+(@)/gi, "$1[REDACTED:CREDENTIAL]$2");

  // pg_dump / psql -W password (positional arg after -W flag)
  out = out.replace(/(pg_dump|psql)(\s+\S+)*\s+-W\s+(\S+)/gi, (m, cmd, mid, pw) => m.replace(pw, "[REDACTED:CREDENTIAL]"));

  // password/passwd/passphrase/pass/pwd followed by colon, equals, or space-value
  // "password: X", "passphrase: X", "password=X", "pass: X", "passwd: X"
  out = out.replace(/\b(password|passwd|passphrase|pass|pwd)\s*[:=]\s*(\S+)/gi, "$1: [REDACTED:PASSWORD]");

  // Multi-word credential labels followed by colon
  // "client secret: X", "private token: X", "access token: X", "api key: X", etc.
  out = out.replace(/\b(client\s+secret|private\s+token|access\s+token|api\s+key|auth\s+token|service\s+account\s+key|signing\s+key|master\s+key|deploy\s+key|session\s+secret|webhook\s+secret|app\s+secret|shared\s+secret)\s*[:=]\s*(\S+)/gi, "$1: [REDACTED:CREDENTIAL]");

  // "password is/was/set to X" — verb phrase
  out = out.replace(/\b(password|passphrase|secret)\s+(is|was|set to|=|:)\s+(\S+)/gi, "$1 $2 [REDACTED:PASSWORD]");

  // "secret <high-entropy-value>" — noun directly before a 16+ char alphanumeric value
  // Catches: "validates using secret Xk9mP2vQ..." with no verb
  out = out.replace(/\bsecret\s+([A-Za-z0-9+/]{16,})\b/g, "secret [REDACTED:SECRET]");

  // "key (<value>)" or "key (<value>)" — token value in parentheses after key/secret/token noun
  out = out.replace(/\b(key|token|secret|credential)\s+\(([A-Za-z0-9+/\-_]{12,})\)/gi, "$1 ([REDACTED:CREDENTIAL])");

  // "set to X for the account" — often follows a password context
  out = out.replace(/(password|passphrase).*?\bset to\s+(\S+)/gi, (m, kw, val) => m.replace(val, "[REDACTED:PASSWORD]"));

  // "# password: X" or "# pass: X" in comments
  out = out.replace(/(#\s*(?:password|pass|passwd)\s*[:=]\s*)(\S+)/gi, "$1[REDACTED:PASSWORD]");

  // curl -u user:password or -u :password basic auth
  out = out.replace(/(curl\s+.*?-u\s+)([^:\s]+):(\S+)/gi, "$1$2:[REDACTED:CREDENTIAL]");

  // sshpass -p <password>
  out = out.replace(/(sshpass\s+-p\s+)(\S+)/gi, "$1[REDACTED:CREDENTIAL]");

  // heroku auth:token output — standalone token value on its own line after a command
  // Catches: "heroku auth:token\n<token>"
  out = out.replace(/(heroku\s+auth:token\s*\n)(\S+)/gi, "$1[REDACTED:TOKEN]");

  // Private key PEM blocks — replace entire block content
  out = out.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi,
    "[REDACTED:PRIVATE_KEY]");

  // GitHub tokens (ghp_, gho_, ghs_, ghr_)
  out = out.replace(/\bgh[posr]_[A-Za-z0-9]{36,}\b/g, "[REDACTED:TOKEN]");

  // npm tokens
  out = out.replace(/\bnpm_[A-Za-z0-9]{36,}\b/g, "[REDACTED:TOKEN]");

  // Stripe keys
  out = out.replace(/\bsk_(live|test)_[A-Za-z0-9]{24,}\b/g, "[REDACTED:TOKEN]");

  // Generic sk- prefixed keys (OpenAI, Anthropic, etc.)
  out = out.replace(/\bsk-[A-Za-z0-9\-_]{20,}\b/g, "[REDACTED:TOKEN]");

  // Slack tokens
  out = out.replace(/\bxox[bpoa]-[A-Za-z0-9\-]{10,}\b/g, "[REDACTED:TOKEN]");

  // JWT tokens (3 base64url segments separated by dots)
  out = out.replace(/\bey[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b/g, "[REDACTED:TOKEN]");

  // Bearer tokens
  out = out.replace(/(Authorization:\s*Bearer\s+)\S+/gi, "$1[REDACTED:TOKEN]");

  // Generic env var assignments — known names
  out = out.replace(/\b(API_KEY|SECRET_KEY|SECRET|PRIVATE_KEY|ACCESS_TOKEN|AUTH_TOKEN|JWT_SECRET|MASTER_KEY|SIGNING_KEY|ENCRYPTION_KEY|NEXTAUTH_SECRET|RAILS_MASTER_KEY|APP_SECRET|CLIENT_SECRET|WEBHOOK_SECRET|SENDGRID_API_KEY|DATADOG_API_KEY|FIREBASE_[A-Z_]+_KEY)\s*=\s*\S+/g,
    (m, varname) => `${varname}=[REDACTED:CREDENTIAL]`);

  // Broad env var suffix pattern — any var ending in _KEY, _SECRET, _TOKEN, _PASSWORD, _PASS, _PWD, _AUTH, _CREDENTIAL
  // Catches vendor-specific names: TWILIO_AUTH_TOKEN, PUSHER_APP_SECRET, STRIPE_SECRET_KEY, etc.
  out = out.replace(/\b[A-Z][A-Z0-9_]*(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_PASS|_PWD|_AUTH|_CREDENTIAL|_APIKEY)\s*=\s*\S+/g,
    (m) => m.replace(/=\S+$/, "=[REDACTED:CREDENTIAL]"));

  // grep/awk with secret value as search term — e.g. grep SECRET=value
  // Catches: kubectl exec pod -- env | grep SECRET=actualvalue
  out = out.replace(/(grep\s+[A-Z_]*(?:SECRET|PASSWORD|TOKEN|KEY|PASS|PWD)=)(\S+)/gi, "$1[REDACTED:CREDENTIAL]");

  // SCP user:pass@host — scp doesn't use -p flag, password is in the path
  // Format: user:password@host:/path
  out = out.replace(/(scp\s+.*?\s+\S+:)([^@\s]+)(@\S+)/gi, "$1[REDACTED:CREDENTIAL]$3");

  // Generic user:password pattern — freeform credential pairs
  // Catches: "user:P@ss123 (staging)", "deploy:&!secret@host", etc.
  // User part: alphanumeric/dots/dashes. Pass part: 8+ chars, any non-whitespace/non-slash
  out = out.replace(/\b([a-zA-Z0-9._-]{2,32}):([\S]{8,})(?=\s*[@()\s,]|$)/g,
    (m, user, pass) => {
      // Only replace if pass looks like a credential — not a plain word or version string
      // Credential signals: has special char, OR mixed case+digits, OR 16+ chars
      const hasSpecial = /[^a-zA-Z0-9]/.test(pass);
      const hasMixedDigits = /[A-Za-z]/.test(pass) && /\d/.test(pass);
      const isLong = pass.length >= 16;
      if (hasSpecial || hasMixedDigits || isLong) {
        return `${user}:[REDACTED:CREDENTIAL]`;
      }
      return m;
    });

  return out;
}

/**
 * Two-step desensitization using a local model:
 *   Step 1: Deterministic regex pre-pass (catches high-confidence patterns)
 *   Step 2: Model identifies remaining PII items as a JSON array
 *   Step 3: Programmatic string replacement using the model's output
 *
 * Falls back to rule-based redaction if the local model is unavailable.
 */
export async function desensitizeWithLocalModel(
  content: string,
  config: PrivacyConfig,
  sessionKey?: string,
): Promise<{ desensitized: string; wasModelUsed: boolean; failed?: boolean }> {
  if (!config.localModel?.enabled) {
    return { desensitized: content, wasModelUsed: false, failed: true };
  }

  // ── Stage 1: Deterministic regex pre-pass ─────────────────────────────────
  // Strip high-confidence credential patterns before the LLM sees them.
  // This catches cases the LLM misses in unusual phrasings (AKIA keys,
  // Redis URLs, pg_dump args, password colon-variants, etc.)
  const preRedacted = preRedactCredentials(content);

  try {
    const endpoint = config.localModel?.endpoint ?? "http://localhost:11434";
    const model = config.localModel?.model ?? "openbmb/minicpm4.1";
    const providerType = config.localModel?.type ?? "openai-compatible";
    const customModule = config.localModel?.module;

    // ── Stage 2: LLM PII extraction on pre-redacted content ─────────────────
    // Send pre-redacted content to LLM — credentials already stripped by regex,
    // LLM focuses on remaining PII (names, emails, phones, addresses, etc.)
    const piiItems = await extractPiiWithModel(endpoint, model, preRedacted, {
      apiKey: config.localModel?.apiKey,
      providerType,
      customModule,
      sessionKey,
      provider: config.localModel?.provider,
    });

    if (piiItems.length === 0) {
      return { desensitized: preRedacted, wasModelUsed: true };
    }

    // ── Stage 3: Programmatic replacement of LLM-identified items ────────────
    let redacted = preRedacted;
    // Sort by value length descending to avoid partial replacements
    const sorted = [...piiItems].sort((a, b) => b.value.length - a.value.length);
    for (const item of sorted) {
      if (!item.value || item.value.length < 2) continue;
      const tag = mapPiiTypeToTag(item.type);
      // Replace all occurrences of this value
      redacted = replaceAll(redacted, item.value, tag);
    }

    return { desensitized: redacted, wasModelUsed: true };
  } catch (err) {
    console.error("[GuardClaw] Local model desensitization failed:", err);
    // On LLM failure, return pre-redacted content (regex pass still applied)
    return { desensitized: preRedacted, wasModelUsed: false, failed: true };
  }
}

/** Map model PII types to [REDACTED:...] tags */
function mapPiiTypeToTag(type: string): string {
  const t = type.toUpperCase().replace(/\s+/g, "_");
  const mapping: Record<string, string> = {
    ADDRESS: "[REDACTED:ADDRESS]",
    ACCESS_CODE: "[REDACTED:ACCESS_CODE]",
    DELIVERY: "[REDACTED:DELIVERY]",
    COURIER_NUMBER: "[REDACTED:DELIVERY]",
    COURIER_NO: "[REDACTED:DELIVERY]",
    COURIER_CODE: "[REDACTED:DELIVERY]",
    TRACKING_NUMBER: "[REDACTED:DELIVERY]",
    NAME: "[REDACTED:NAME]",
    SENDER_NAME: "[REDACTED:NAME]",
    RECIPIENT_NAME: "[REDACTED:NAME]",
    PHONE: "[REDACTED:PHONE]",
    SENDER_PHONE: "[REDACTED:PHONE]",
    FACILITY_PHONE: "[REDACTED:PHONE]",
    LANDLINE: "[REDACTED:PHONE]",
    MOBILE: "[REDACTED:PHONE]",
    EMAIL: "[REDACTED:EMAIL]",
    ID: "[REDACTED:ID]",
    ID_CARD: "[REDACTED:ID]",
    ID_NUMBER: "[REDACTED:ID]",
    CARD: "[REDACTED:CARD]",
    BANK_CARD: "[REDACTED:CARD]",
    CARD_NUMBER: "[REDACTED:CARD]",
    SECRET: "[REDACTED:SECRET]",
    PASSWORD: "[REDACTED:SECRET]",
    API_KEY: "[REDACTED:SECRET]",
    TOKEN: "[REDACTED:SECRET]",
    IP: "[REDACTED:IP]",
    LICENSE_PLATE: "[REDACTED:LICENSE]",
    PLATE: "[REDACTED:LICENSE]",
    TIME: "[REDACTED:TIME]",
    DATE: "[REDACTED:DATE]",
    SALARY: "[REDACTED:SALARY]",
    AMOUNT: "[REDACTED:AMOUNT]",
    // Credential types
    AWS_KEY: "[REDACTED:CREDENTIAL]",
    PRIVATE_KEY: "[REDACTED:PRIVATE_KEY]",
    CONNECTION_STRING: "[REDACTED:CREDENTIAL]",
    ENV_VAR: "[REDACTED:CREDENTIAL]",
    CREDENTIAL: "[REDACTED:CREDENTIAL]",
    MFA_CODE: "[REDACTED:SECRET]",
    CERT: "[REDACTED:CREDENTIAL]",
  };
  return mapping[t] ?? `[REDACTED:${t}]`;
}

/** Simple replaceAll polyfill for older Node */
function replaceAll(str: string, search: string, replacement: string): string {
  // Escape regex special chars in search string
  const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return str.replace(new RegExp(escaped, "g"), replacement);
}

/** Default PII extraction system prompt (fallback if prompts/pii-extraction.md is missing) */
export const DEFAULT_PII_EXTRACTION_PROMPT = `You are a PII extraction engine. Extract ALL PII (personally identifiable information) from the given text as a JSON array.

Types: NAME (every person), PHONE, ADDRESS (all variants including shortened), ACCESS_CODE (gate/door/门禁码), DELIVERY (tracking numbers, pickup codes/取件码), ID (SSN/身份证), CARD (bank/medical/insurance), LICENSE_PLATE (plate numbers/车牌), EMAIL, PASSWORD, PAYMENT (Venmo/PayPal/支付宝), BIRTHDAY, TIME (appointment/delivery times), NOTE (private instructions)

Important: Extract EVERY person's name and EVERY address variant.

Example:
Input: Alex lives at 123 Main St. Li Na phone 13912345678, gate code 1234#, card YB330-123, plate 京A12345, tracking SF123, Venmo @alex99
Output: [{"type":"NAME","value":"Alex"},{"type":"NAME","value":"Li Na"},{"type":"ADDRESS","value":"123 Main St"},{"type":"PHONE","value":"13912345678"},{"type":"ACCESS_CODE","value":"1234#"},{"type":"CARD","value":"YB330-123"},{"type":"LICENSE_PLATE","value":"京A12345"},{"type":"DELIVERY","value":"SF123"},{"type":"PAYMENT","value":"@alex99"}]

Output ONLY the JSON array — no explanation, no markdown fences.`;

/**
 * Extract PII from content using local model via chat completions.
 *
 * Two-step approach: model identifies PII items as JSON, then we do
 * programmatic string replacement. More reliable than asking models to rewrite.
 */
async function extractPiiWithModel(
  endpoint: string,
  model: string,
  content: string,
  opts?: {
    apiKey?: string;
    providerType?: EdgeProviderType;
    customModule?: string;
    sessionKey?: string;
    provider?: string;
  },
): Promise<Array<{ type: string; value: string }>> {
  const textSnippet = content.slice(0, 3000);

  const systemPrompt = loadPromptWithVars("pii-extraction", DEFAULT_PII_EXTRACTION_PROMPT, {
    CONTENT: textSnippet,
  });

  const promptHasContent = systemPrompt.includes(textSnippet) && textSnippet.length > 10;
  const userMessage = promptHasContent
    ? "Extract all PII from the text above. Output ONLY the JSON array."
    : textSnippet;

  const result = await callChatCompletion(
    endpoint,
    model,
    [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage },
    ],
    {
      temperature: 0.0,
      maxTokens: 2500,
      stop: ["Input:", "Task:"],
      apiKey: opts?.apiKey,
      disableThinking: true,
      providerType: opts?.providerType,
      customModule: opts?.customModule,
    },
  );

  if (result.usage) {
    const collector = getGlobalCollector();
    collector?.record({
      sessionKey: opts?.sessionKey ?? "",
      provider: "edge",
      model,
      source: "router",
      usage: result.usage,
    });
    recordRouterOperation(opts?.sessionKey, "desensitization", result.usage, model, opts?.provider);
  }

  return parsePiiJson(result.text);
}

/** Parse the model's PII extraction output into structured items */
function parsePiiJson(raw: string): Array<{ type: string; value: string }> {
  // Normalize whitespace (model may use newlines between items)
  let cleaned = raw.replace(/\s+/g, " ").trim();

  // Strip markdown code fences if present
  cleaned = cleaned
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();

  // Find the JSON array in the output
  const arrayStart = cleaned.indexOf("[");
  if (arrayStart < 0) return [];
  let jsonStr = cleaned.slice(arrayStart);

  // Find the last ] to cut off any trailing garbage
  const lastBracket = jsonStr.lastIndexOf("]");
  if (lastBracket >= 0) {
    jsonStr = jsonStr.slice(0, lastBracket + 1);
  } else {
    const lastCloseBrace = jsonStr.lastIndexOf("}");
    if (lastCloseBrace >= 0) {
      jsonStr = jsonStr.slice(0, lastCloseBrace + 1) + "]";
    } else {
      return [];
    }
  }

  // Fix trailing commas before ]
  jsonStr = jsonStr.replace(/,\s*\]/g, "]");

  // Normalize Python-style single-quoted JSON to double-quoted JSON.
  // Some local models output {'key': 'value'} instead of {"key": "value"}.
  jsonStr = jsonStr
    .replace(/(?<=[\[,{]\s*)'([^']+?)'(?=\s*:)/g, '"$1"')
    .replace(/(?<=:\s*)'([^']*?)'(?=\s*[,}\]])/g, '"$1"');

  try {
    const arr = JSON.parse(jsonStr);
    if (!Array.isArray(arr)) return [];
    const items = arr.filter(
      (item: unknown) =>
        item &&
        typeof item === "object" &&
        typeof (item as Record<string, unknown>).type === "string" &&
        typeof (item as Record<string, unknown>).value === "string",
    ) as Array<{ type: string; value: string }>;
    return items;
  } catch {
    console.error("[GuardClaw] Failed to parse PII extraction JSON:", jsonStr.slice(0, 300));
    return [];
  }
}

/**
 * Parse model response to extract sensitivity level
 */
function parseModelResponse(response: string): {
  level: SensitivityLevel;
  reason?: string;
  confidence?: number;
} {
  try {
    // Try to find JSON in the response
    const jsonMatch = response.match(/\{[\s\S]*?\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]) as {
        level?: string;
        reason?: string;
        confidence?: number;
      };

      // Validate level
      const level = parsed.level?.toUpperCase();
      if (level === "S1" || level === "S2" || level === "S3") {
        return {
          level: level as SensitivityLevel,
          reason: parsed.reason,
          confidence: parsed.confidence,
        };
      }
    }

    // Fallback: look for level mentions in text
    const upperResponse = response.toUpperCase();
    if (upperResponse.includes("S3") || upperResponse.includes("PRIVATE")) {
      return {
        level: "S3",
        reason: "Detected from text analysis",
        confidence: 0.6,
      };
    }
    if (upperResponse.includes("S2") || upperResponse.includes("SENSITIVE")) {
      return {
        level: "S2",
        reason: "Detected from text analysis",
        confidence: 0.6,
      };
    }

    // Default to S1 if unable to parse
    return {
      level: "S1",
      reason: "Unable to parse model response",
      confidence: 0.3,
    };
  } catch (err) {
    console.error("[GuardClaw] Error parsing model response:", err);
    return {
      level: "S1",
      reason: "Parse error",
      confidence: 0,
    };
  }
}
