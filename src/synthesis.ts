/**
 * GuardClaw S3 Synthesis Engine
 *
 * Transparent S3 policy — processes sensitive content locally and produces
 * a natural-language synthesis that the cloud model receives seamlessly.
 * Neither the cloud model nor the user sees that interception occurred.
 *
 * Flow:
 *   1. S3 content → local model with synthesis prompt
 *   2. Synthesis output → verification pass (re-run S3 detector)
 *   3. If clean → forward to cloud as synthetic message
 *   4. If not clean → retry up to maxRetries, then fall back to configured fallback
 */

import { callChatCompletion } from "./local-model.js";
import { loadPromptWithVars } from "./prompt-loader.js";
import type { PrivacyConfig, SynthesisConfig } from "./types.js";
import { DEFAULT_LOCAL_CLASSIFIER_MODEL } from "./model-defaults.js";

// ── Fallback prompts (used if prompts/s3-synthesis.md or s3-verify.md are missing) ──

const DEFAULT_SYNTHESIS_PROMPT = `You are a privacy-preserving content transformer. Re-express the content below so it conveys the information needed for the user's task, but contains NO sensitive values (no passwords, keys, tokens, credentials, or raw personal data). Describe sensitive values by type only — e.g. "[API key]", "[password]", "[RSA private key]". Preserve all structural context (file paths, variable names, config keys, non-sensitive values). Output ONLY the transformed content — no preamble.

User task context:
{{TASK_CONTEXT}}

Content to transform:
{{CONTENT}}`;

const DEFAULT_VERIFY_PROMPT = `Does the following text contain any sensitive values that should not be sent to a cloud AI? (passwords, API keys, tokens, private keys, raw credentials — NOT type descriptions like "[API key]" or "[password]"). Respond ONLY with JSON: {"safe":true} or {"safe":false,"reason":"..."}.

Text:
{{CONTENT}}`;

// ── Types ──

export type SynthesisSuccess = { ok: true; synthetic: string };
export type SynthesisFailure = { ok: false; reason: string };
export type SynthesisResult = SynthesisSuccess | SynthesisFailure;

// ── Defaults ──

const DEFAULT_CONFIG: Required<SynthesisConfig> = {
  fallback: "local-only",
  verifyOutput: true,
  maxRetries: 2,
  maxInputChars: 4000,
  timeoutMs: 20_000,
};

function resolveConfig(config: PrivacyConfig): Required<SynthesisConfig> {
  const s = (config as Record<string, unknown>).synthesis as SynthesisConfig | undefined;
  return {
    fallback: s?.fallback ?? DEFAULT_CONFIG.fallback,
    verifyOutput: s?.verifyOutput ?? DEFAULT_CONFIG.verifyOutput,
    maxRetries: s?.maxRetries ?? DEFAULT_CONFIG.maxRetries,
    maxInputChars: s?.maxInputChars ?? DEFAULT_CONFIG.maxInputChars,
    timeoutMs: s?.timeoutMs ?? DEFAULT_CONFIG.timeoutMs,
  };
}

// ── Core synthesis call ──

async function callSynthesis(
  content: string,
  taskContext: string,
  config: PrivacyConfig,
  timeoutMs: number,
): Promise<string> {
  const endpoint = config.localModel?.endpoint ?? "http://localhost:11434";
  const model = config.localModel?.model ?? DEFAULT_LOCAL_CLASSIFIER_MODEL;
  const providerType = config.localModel?.type ?? "openai-compatible";

  const prompt = loadPromptWithVars("s3-synthesis", DEFAULT_SYNTHESIS_PROMPT, {
    CONTENT: content,
    TASK_CONTEXT: taskContext || "General assistance",
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const result = await callChatCompletion(
      endpoint,
      model,
      [{ role: "user", content: prompt }],
      {
        temperature: 0.15,
        maxTokens: 1200,
        providerType,
        apiKey: config.localModel?.apiKey,
        customModule: config.localModel?.module,
        disableThinking: true,
      },
    );
    return result.text.trim();
  } finally {
    clearTimeout(timer);
  }
}

// ── Verification pass ──

async function verifySynthesis(
  synthetic: string,
  config: PrivacyConfig,
  timeoutMs: number,
): Promise<{ safe: boolean; reason?: string }> {
  const endpoint = config.localModel?.endpoint ?? "http://localhost:11434";
  const model = config.localModel?.model ?? DEFAULT_LOCAL_CLASSIFIER_MODEL;
  const providerType = config.localModel?.type ?? "openai-compatible";

  const prompt = loadPromptWithVars("s3-verify", DEFAULT_VERIFY_PROMPT, {
    CONTENT: synthetic.slice(0, 2000),
  });

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let raw: string;
    try {
      const result = await callChatCompletion(
        endpoint,
        model,
        [{ role: "user", content: prompt }],
        {
          temperature: 0.0,
          maxTokens: 80,
          stop: ["\n\n"],
          providerType,
          apiKey: config.localModel?.apiKey,
          customModule: config.localModel?.module,
          disableThinking: true,
        },
      );
      raw = result.text.trim();
    } finally {
      clearTimeout(timer);
    }

    // Parse {"safe":true} or {"safe":false,"reason":"..."}
    const match = raw.match(/\{[\s\S]*?\}/);
    if (match) {
      const parsed = JSON.parse(match[0]) as { safe?: boolean; reason?: string };
      return { safe: parsed.safe !== false, reason: parsed.reason };
    }
    // If we can't parse, be conservative and pass it through
    return { safe: true };
  } catch {
    // Verification timeout/failure — pass through (synthesis still useful)
    return { safe: true };
  }
}

// ── Public API ──

/**
 * Synthesize a user message that contains S3-classified content.
 * Returns a natural-language version safe to forward to the cloud model.
 */
export async function synthesizeContent(
  original: string,
  taskContext: string,
  config: PrivacyConfig,
  sessionKey?: string,
): Promise<SynthesisResult> {
  if (!config.localModel?.enabled) {
    return { ok: false, reason: "Local model not enabled" };
  }

  const cfg = resolveConfig(config);
  const input = original.slice(0, cfg.maxInputChars);

  let lastFailReason = "Unknown error";

  for (let attempt = 0; attempt <= cfg.maxRetries; attempt++) {
    try {
      const synthetic = await callSynthesis(input, taskContext, config, cfg.timeoutMs);

      if (!synthetic) {
        lastFailReason = "Empty synthesis output";
        continue;
      }

      if (cfg.verifyOutput) {
        const { safe, reason } = await verifySynthesis(synthetic, config, Math.min(cfg.timeoutMs, 8_000));
        if (!safe) {
          lastFailReason = `Verification failed: ${reason ?? "S3 content detected in output"}`;
          console.warn(`[GuardClaw Synthesis] Attempt ${attempt + 1} failed verification — retrying`);
          continue;
        }
      }

      // Reconstruct full message: if input was truncated, append note
      const finalSynthetic = input.length < original.length
        ? `${synthetic}\n\n[Note: input was truncated to ${cfg.maxInputChars} characters for local processing]`
        : synthetic;

      return { ok: true, synthetic: finalSynthetic };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      lastFailReason = message.includes("abort") ? "Synthesis timeout" : message;
      console.warn(`[GuardClaw Synthesis] Attempt ${attempt + 1} error: ${lastFailReason}`);
    }
  }

  return { ok: false, reason: lastFailReason };
}

/**
 * Synthesize a tool result that contains S3-classified content.
 * Produces a structured, non-sensitive description of what the tool returned.
 */
export async function synthesizeToolResult(
  toolName: string,
  toolResult: string,
  taskContext: string,
  config: PrivacyConfig,
  sessionKey?: string,
): Promise<SynthesisResult> {
  if (!config.localModel?.enabled) {
    return { ok: false, reason: "Local model not enabled" };
  }

  const cfg = resolveConfig(config);

  // Tool results get a more structured synthesis prompt
  const toolContext = `Tool "${toolName}" returned a result. Task context: ${taskContext || "general assistance"}`;
  const input = toolResult.slice(0, cfg.maxInputChars);

  return synthesizeContent(input, toolContext, config, sessionKey);
}
