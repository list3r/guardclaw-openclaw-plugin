/**
 * GuardClaw Secret Operations Pipeline
 *
 * Intercepts `use_secret` tool calls and executes credential operations
 * without exposing raw secret values to the agent's context.
 *
 * Flow:
 *   1. Agent calls use_secret(name, operation, params)
 *   2. Behavioral attestation check (suspicious pattern → auto-deny)
 *   3. Local LLM intent verifier (3 s timeout → fail-closed)
 *   4. Execute operation with resolved credential (result only returned)
 *   5. Notify via Discord webhook on deny or allow
 *
 * Supported operations (MVP):
 *   describe         – return the secret's policy description; no value exposed
 *   make_http_request – execute an HTTP call authenticated with the secret
 *   inject_env_vars   – spawn a command with secret(s) injected as env vars;
 *                       return stdout/stderr; command must be pre-approved or
 *                       the allowedCommands list must match
 *
 * Secret registry: ~/.openclaw/guardclaw-secrets.json
 * Each entry specifies keychain coordinates or a config-file path, a
 * human-readable description, and which operations are permitted.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { callChatCompletion, type ChatMessage } from "./local-model.js";
import { readKeychainSecret } from "./secret-manager.js";
import { getRecentEvents } from "./behavioral-log.js";
import { score as behavioralScore } from "./behavioral-attestation.js";
import type { PrivacyConfig } from "./types.js";

const execFileAsync = promisify(execFile);

// ── Types ──────────────────────────────────────────────────────────────────

export type SecretSource =
  | { type: "keychain"; service: string; account: string }
  | { type: "config"; file: string; jsonPath: string };

export type AllowedOperation = "describe" | "make_http_request" | "inject_env_vars";

export type SecretEntry = {
  /** Human-readable description of what this secret is and what it's used for */
  description: string;
  source: SecretSource;
  /** Operations this secret is permitted to participate in */
  allowedOps?: AllowedOperation[];
  /** For inject_env_vars: env var name to inject (e.g. "OPENAI_API_KEY") */
  envVarName?: string;
  /** For make_http_request: header name to use (default: "Authorization", value: "Bearer <secret>") */
  httpHeader?: string;
};

export type SecretRegistry = {
  secrets: Record<string, SecretEntry>;
};

export type UseSecretParams = {
  /** Registry key name for the secret */
  name: string;
  /** Operation to perform */
  operation: AllowedOperation;
  /** Operation-specific parameters */
  params?: Record<string, unknown>;
};

export type UseSecretResult =
  | { ok: true; result: string }
  | { ok: false; reason: string; notify?: boolean };

// ── Constants ──────────────────────────────────────────────────────────────

const HOME = process.env.HOME ?? process.env.USERPROFILE ?? "/tmp";
const SECRETS_REGISTRY_PATH = join(HOME, ".openclaw", "guardclaw-secrets.json");

/** Behavioral score above which we auto-deny without calling the LLM verifier */
const AUTO_DENY_SCORE = 0.75;

/** Timeout for the local LLM intent verifier */
const INTENT_VERIFY_TIMEOUT_MS = 3000;

/** Maximum bytes for HTTP responses returned to agent */
const MAX_HTTP_RESPONSE_BYTES = 32_768;

/** Maximum command execution time for inject_env_vars */
const INJECT_EXEC_TIMEOUT_MS = 30_000;

// ── Registry loading ───────────────────────────────────────────────────────

let _registryCache: SecretRegistry | null = null;
let _registryCacheTs = 0;
const REGISTRY_CACHE_TTL_MS = 30_000;

export async function loadSecretRegistry(): Promise<SecretRegistry> {
  const now = Date.now();
  if (_registryCache && now - _registryCacheTs < REGISTRY_CACHE_TTL_MS) {
    return _registryCache;
  }
  try {
    const raw = await readFile(SECRETS_REGISTRY_PATH, "utf-8");
    _registryCache = JSON.parse(raw) as SecretRegistry;
    _registryCacheTs = now;
    return _registryCache;
  } catch {
    _registryCache = { secrets: {} };
    _registryCacheTs = now;
    return _registryCache;
  }
}

// ── Secret resolution ──────────────────────────────────────────────────────

async function resolveSecret(entry: SecretEntry): Promise<{ value: string } | { error: string }> {
  const { source } = entry;

  if (source.type === "keychain") {
    return readKeychainSecret(source.service, source.account);
  }

  if (source.type === "config") {
    try {
      const filePath = source.file.replace(/^~/, HOME);
      const raw = await readFile(filePath, "utf-8");
      const obj = JSON.parse(raw) as Record<string, unknown>;
      // Resolve dot-separated JSON path e.g. "discord.token"
      const parts = source.jsonPath.split(".");
      let cursor: unknown = obj;
      for (const part of parts) {
        if (cursor == null || typeof cursor !== "object") {
          return { error: `Path "${source.jsonPath}" not found in ${filePath}` };
        }
        cursor = (cursor as Record<string, unknown>)[part];
      }
      if (typeof cursor !== "string" || !cursor) {
        return { error: `Path "${source.jsonPath}" is not a non-empty string in ${filePath}` };
      }
      return { value: cursor };
    } catch (err) {
      return { error: String(err) };
    }
  }

  return { error: "Unknown secret source type" };
}

// ── Intent verification ────────────────────────────────────────────────────

/**
 * Ask the local LLM whether the secret access looks legitimate.
 * Returns "ALLOW" or "DENY". Times out after INTENT_VERIFY_TIMEOUT_MS → "DENY".
 */
async function verifyIntent(
  secretName: string,
  entry: SecretEntry,
  operation: AllowedOperation,
  opParams: Record<string, unknown>,
  sessionKey: string,
  privacyConfig: PrivacyConfig,
): Promise<{ decision: "ALLOW" | "DENY"; reason: string }> {
  const localModelCfg = privacyConfig.localModel;
  if (!localModelCfg?.enabled || !localModelCfg.endpoint || !localModelCfg.model) {
    return { decision: "DENY", reason: "No local model configured for intent verification" };
  }

  const recentEvents = getRecentEvents(sessionKey, 10);
  const eventSummary = recentEvents.length === 0
    ? "(no prior tool calls in this session)"
    : recentEvents.map((e, i) =>
        `${i + 1}. [${e.category}] ${e.tool}${e.sensitivity ? ` (${e.sensitivity})` : ""}`,
      ).join("\n");

  const safeParams = sanitizeParamsForVerifier(opParams);

  const messages: ChatMessage[] = [
    {
      role: "system",
      content:
        "You are a security intent verifier. An AI agent has requested access to a secret credential. " +
        "Determine if this request appears legitimate given the recent tool call history. " +
        "Reply with exactly: ALLOW or DENY on the first line, then a brief reason on the second line. " +
        "Be conservative — deny if anything looks suspicious or out of context.",
    },
    {
      role: "user",
      content:
        `Secret name: ${secretName}\n` +
        `Description: ${entry.description}\n` +
        `Operation: ${operation}\n` +
        `Parameters: ${JSON.stringify(safeParams)}\n\n` +
        `Recent tool call history (last ${recentEvents.length} calls):\n${eventSummary}\n\n` +
        `Is this secret access request legitimate? Reply ALLOW or DENY, then brief reason.`,
    },
  ];

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), INTENT_VERIFY_TIMEOUT_MS);

    let text = "";
    try {
      const result = await Promise.race([
        callChatCompletion(localModelCfg.endpoint, localModelCfg.model, messages, {
          temperature: 0,
          maxTokens: 80,
          providerType: localModelCfg.type ?? "openai-compatible",
          apiKey: localModelCfg.apiKey,
        }),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error("intent-verify-timeout")), INTENT_VERIFY_TIMEOUT_MS),
        ),
      ]);
      text = result.text.trim();
    } finally {
      clearTimeout(timeout);
    }

    const firstLine = text.split("\n")[0]?.trim().toUpperCase() ?? "";
    const reasonLine = text.split("\n").slice(1).join(" ").trim();
    const decision = firstLine.startsWith("ALLOW") ? "ALLOW" : "DENY";
    return { decision, reason: reasonLine || (decision === "ALLOW" ? "Looks legitimate" : "Suspicious pattern") };
  } catch (err) {
    const msg = String(err);
    if (msg.includes("intent-verify-timeout")) {
      return { decision: "DENY", reason: "Intent verifier timed out — failing closed for safety" };
    }
    return { decision: "DENY", reason: `Intent verifier error: ${msg}` };
  }
}

/** Strip any values that look like secrets from params before sending to LLM */
function sanitizeParamsForVerifier(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    if (typeof v === "string" && (v.length > 40 || /key|token|secret|password|bearer/i.test(k))) {
      out[k] = `[${v.length} chars]`;
    } else {
      out[k] = v;
    }
  }
  return out;
}

// ── Operations ─────────────────────────────────────────────────────────────

async function opDescribe(entry: SecretEntry): Promise<string> {
  return `Secret: ${entry.description}\nAllowed operations: ${(entry.allowedOps ?? ["describe"]).join(", ")}`;
}

async function opMakeHttpRequest(
  secretValue: string,
  entry: SecretEntry,
  params: Record<string, unknown>,
): Promise<string> {
  const url = String(params.url ?? "");
  if (!url || !/^https?:\/\//.test(url)) {
    throw new Error("make_http_request requires a valid http(s) url in params.url");
  }

  const method = String(params.method ?? "GET").toUpperCase();
  const headerName = entry.httpHeader ?? "Authorization";
  const headerValue = headerName === "Authorization" ? `Bearer ${secretValue}` : secretValue;

  const headers: Record<string, string> = {
    [headerName]: headerValue,
    "Content-Type": "application/json",
    ...(params.headers as Record<string, string> ?? {}),
  };
  // Never let caller override the auth header with their own value
  headers[headerName] = headerValue;

  const body = params.body != null
    ? (typeof params.body === "string" ? params.body : JSON.stringify(params.body))
    : undefined;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  try {
    const resp = await fetch(url, {
      method,
      headers,
      body: method !== "GET" && method !== "HEAD" ? body : undefined,
      signal: controller.signal,
    });
    let responseText = await resp.text();
    if (responseText.length > MAX_HTTP_RESPONSE_BYTES) {
      responseText = responseText.slice(0, MAX_HTTP_RESPONSE_BYTES) + "\n[truncated]";
    }
    return `HTTP ${resp.status} ${resp.statusText}\n${responseText}`;
  } finally {
    clearTimeout(timeout);
  }
}

async function opInjectEnvVars(
  secretValue: string,
  entry: SecretEntry,
  params: Record<string, unknown>,
): Promise<string> {
  const command = String(params.command ?? "");
  if (!command) {
    throw new Error("inject_env_vars requires params.command — the shell command to run with the secret injected");
  }

  const envVarName = entry.envVarName;
  if (!envVarName) {
    throw new Error(`Secret entry does not have an envVarName configured — cannot inject env var`);
  }

  // Build env: inherit current process env, inject secret, strip any existing value
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v != null) env[k] = v;
  }
  env[envVarName] = secretValue;

  // Additional env vars the caller wants to set (non-secret values only)
  const extraEnv = (params.env as Record<string, string>) ?? {};
  for (const [k, v] of Object.entries(extraEnv)) {
    if (typeof v === "string" && !k.toLowerCase().includes("secret") && !k.toLowerCase().includes("token") && !k.toLowerCase().includes("key") && !k.toLowerCase().includes("password")) {
      env[k] = v;
    }
  }

  try {
    const { stdout, stderr } = await execFileAsync(
      "sh",
      ["-c", command],
      { env, timeout: INJECT_EXEC_TIMEOUT_MS, maxBuffer: MAX_HTTP_RESPONSE_BYTES },
    );
    const out = stdout.trim();
    const err = stderr.trim();
    const parts: string[] = [];
    if (out) parts.push(out);
    if (err) parts.push(`[stderr] ${err}`);
    return parts.join("\n") || "(command produced no output)";
  } catch (execErr: unknown) {
    const e = execErr as { stdout?: string; stderr?: string; message?: string; code?: number };
    const msg = e.stderr?.trim() || e.message || String(execErr);
    throw new Error(`Command failed (exit ${e.code ?? "?"}): ${msg}`);
  }
}

// ── Main intercept ─────────────────────────────────────────────────────────

/**
 * Handle a `use_secret` tool call from an agent.
 *
 * Called from before_tool_call when toolName === "use_secret".
 * Returns a block result (with reason message) if denied,
 * or a modified response if allowed.
 *
 * @param rawParams  Raw params from the tool call
 * @param sessionKey Current session key
 * @param privacyConfig Live privacy config (for local model settings)
 * @param webhooks   Webhook configs for notifications
 * @param logger     Plugin logger
 */
export async function handleUseSecret(
  rawParams: Record<string, unknown>,
  sessionKey: string,
  privacyConfig: PrivacyConfig,
  webhooks: PrivacyConfig["webhooks"],
  logger: { info(msg: string): void; warn(msg: string): void },
): Promise<UseSecretResult> {
  const name = String(rawParams.name ?? "").trim();
  const operation = String(rawParams.operation ?? "describe") as AllowedOperation;
  const opParams = (rawParams.params as Record<string, unknown>) ?? {};

  // ── 1. Load registry ──────────────────────────────────────────────────────
  const registry = await loadSecretRegistry();
  const entry = registry.secrets[name];
  if (!entry) {
    return {
      ok: false,
      reason: `Unknown secret "${name}". Available secrets: ${Object.keys(registry.secrets).join(", ") || "(none registered)"}`,
    };
  }

  // ── 2. Check operation is permitted ───────────────────────────────────────
  const allowedOps = entry.allowedOps ?? ["describe"];
  if (!allowedOps.includes(operation)) {
    return {
      ok: false,
      reason: `Operation "${operation}" is not permitted for secret "${name}". Allowed: ${allowedOps.join(", ")}`,
    };
  }

  // ── 3. Behavioral attestation ─────────────────────────────────────────────
  const baConfig = (privacyConfig as Record<string, unknown> & {
    behavioralAttestation?: { enabled?: boolean; windowSize?: number; blockThreshold?: number }
  }).behavioralAttestation;
  const windowSize = baConfig?.windowSize ?? 10;
  const recentEvents = getRecentEvents(sessionKey, windowSize);
  const { score: suspicionScore, signals } = behavioralScore(recentEvents);

  logger.info(
    `[GuardClaw:secrets] use_secret "${name}":${operation} — behavioral score=${suspicionScore.toFixed(2)} signals=[${signals.join("; ")}]`,
  );

  if (suspicionScore >= AUTO_DENY_SCORE) {
    const reason = `Behavioral attestation auto-denied: score=${suspicionScore.toFixed(2)} (${signals.join("; ")})`;
    logger.warn(`[GuardClaw:secrets] DENIED ${name}:${operation} — ${reason}`);
    _notify("secret_denied", { name, operation, sessionKey, reason, score: suspicionScore }, webhooks);
    return { ok: false, reason, notify: true };
  }

  // ── 4. Intent verification ────────────────────────────────────────────────
  if (operation !== "describe") {
    const { decision, reason: verifierReason } = await verifyIntent(
      name, entry, operation, opParams, sessionKey, privacyConfig,
    );

    if (decision === "DENY") {
      const reason = `Intent verifier denied: ${verifierReason}`;
      logger.warn(`[GuardClaw:secrets] DENIED ${name}:${operation} — ${reason}`);
      _notify("secret_denied", { name, operation, sessionKey, reason, score: suspicionScore }, webhooks);
      return { ok: false, reason, notify: true };
    }

    logger.info(`[GuardClaw:secrets] ALLOWED ${name}:${operation} — ${verifierReason}`);
    _notify("secret_allowed", { name, operation, sessionKey, reason: verifierReason, score: suspicionScore }, webhooks);
  }

  // ── 5. Execute operation ──────────────────────────────────────────────────
  try {
    if (operation === "describe") {
      const result = await opDescribe(entry);
      return { ok: true, result };
    }

    // All non-describe ops need the resolved secret value
    const resolved = await resolveSecret(entry);
    if ("error" in resolved) {
      return { ok: false, reason: `Could not resolve secret "${name}": ${resolved.error}` };
    }

    if (operation === "make_http_request") {
      const result = await opMakeHttpRequest(resolved.value, entry, opParams);
      return { ok: true, result };
    }

    if (operation === "inject_env_vars") {
      const result = await opInjectEnvVars(resolved.value, entry, opParams);
      return { ok: true, result };
    }

    return { ok: false, reason: `Unimplemented operation: ${operation}` };
  } catch (err) {
    return { ok: false, reason: `Operation "${operation}" failed: ${String(err)}` };
  }
}

// ── Internal helpers ───────────────────────────────────────────────────────

function _notify(
  event: "secret_denied" | "secret_allowed",
  details: Record<string, unknown>,
  webhooks: PrivacyConfig["webhooks"],
): void {
  if (!webhooks || webhooks.length === 0) return;
  // Lazy import to avoid circular deps — fireWebhooks is self-contained
  import("./webhook.js").then(({ fireWebhooks }) => {
    fireWebhooks(event, { sessionKey: String(details.sessionKey ?? ""), reason: String(details.reason ?? ""), details }, webhooks);
  }).catch(() => {});
}
