/**
 * GuardClaw Guard Agent Management
 *
 * Manages guard agent configuration and session routing for S3 (private) operations.
 *
 * The guard agent is a sub-agent that runs exclusively with local models.
 * When S3 content is detected, the resolve_model hook redirects the message
 * to a guard subsession. This module provides utilities for:
 * - Guard agent configuration validation
 * - Guard session key generation and detection
 * - Placeholder message generation for the main session history
 */

import type { PrivacyConfig, SensitivityLevel } from "./types.js";

/**
 * Check if the guard agent has a provider configured.
 * GuardClaw requires an explicit provider — there is no hardcoded default.
 */
export function isGuardAgentConfigured(config: PrivacyConfig): boolean {
  return Boolean(config.guardAgent?.provider);
}

/**
 * Get guard agent configuration. Returns null if no provider is configured.
 *
 * Config shape (guardclaw.json → privacy.guardAgent):
 *
 *   provider  — required. Any OpenClaw provider alias defined in openclaw.json.
 *               Examples: "ollama", "ollama-remote", "ollama-120",
 *                         "financial-llm", "image-llm", "vllm-gpu2"
 *               This is the ONLY required field. GuardClaw has no hardcoded default.
 *
 *   model     — optional. Pin a specific model within the provider.
 *               Omit to use whatever model the provider resolves by default.
 *               Examples: "llama3.2:3b", "qwen3:14b"
 *
 *   id        — optional. Sub-session identifier. Default: "guard".
 *   workspace — optional. Guard agent workspace path. Default: "~/.openclaw/workspace-guard".
 *
 * If provider is not set, getGuardAgentConfig returns null and GuardClaw
 * will emit a startup warning — S3 content will not be routed until configured.
 */
export function getGuardAgentConfig(config: PrivacyConfig): {
  id: string;
  workspace: string;
  provider: string;
  /** Undefined when no model is pinned — OpenClaw resolves from the provider config. */
  modelName: string | undefined;
} | null {
  if (!isGuardAgentConfigured(config)) {
    return null;
  }

  return {
    id:        config.guardAgent?.id       ?? "guard",
    workspace: config.guardAgent?.workspace ?? "~/.openclaw/workspace-guard",
    provider:  config.guardAgent!.provider!,
    modelName: config.guardAgent?.model || undefined,
  };
}

/**
 * Emit a one-time startup warning if the guard agent provider is not configured.
 * Call this during plugin initialisation.
 */
export function warnIfGuardAgentUnconfigured(config: PrivacyConfig, logger?: { warn: (msg: string) => void }): void {
  if (!isGuardAgentConfigured(config)) {
    const msg =
      "[GuardClaw] WARNING: privacy.guardAgent.provider is not set. " +
      "S3 (private) content will not be routed to a local model until you configure it. " +
      "Set \"provider\" to any OpenClaw provider alias in your guardclaw.json " +
      "(e.g. \"ollama\", \"ollama-remote\", \"financial-llm\").";
    if (logger?.warn) logger.warn(msg);
    else console.warn(msg);
  }
}

/**
 * Check if a session key belongs to a guard subsession (pattern-based).
 *
 * NOTE: Use isVerifiedGuardSession() for elevated-trust checks (file access,
 * Keychain, full history).  This function is kept for backward compatibility
 * with OpenClaw SDK callbacks that only have the session key available and
 * cannot block on the registry.
 */
export function isGuardSessionKey(sessionKey: string): boolean {
  return sessionKey.endsWith(":guard") || sessionKey.includes(":guard:");
}

// ── Guard session registry (#12) ──────────────────────────────────────────────
//
// Pattern-only matching (isGuardSessionKey) is exploitable if an attacker
// can influence the session key to contain ":guard".  The registry tracks
// parent session keys that legitimately routed to a guard agent so we can
// cross-check before granting elevated trust.

const registeredGuardParents = new Set<string>();

/**
 * Register a parent session key as having legitimately spawned a guard session.
 * Called from hooks.ts whenever before_model_resolve routes to the guard agent.
 * The guard session key is expected to be `parentKey + ":guard[...]"`.
 */
export function registerGuardSessionParent(parentSessionKey: string): void {
  registeredGuardParents.add(parentSessionKey);
}

/**
 * Returns true only when BOTH conditions hold:
 *   1. The key looks like a guard session (isGuardSessionKey)
 *   2. The parent session was explicitly registered when S3 was detected
 *
 * Use this for all elevated-trust decisions (full history access, Keychain,
 * network-tool blocking) instead of bare isGuardSessionKey().
 */
export function isVerifiedGuardSession(sessionKey: string): boolean {
  if (!isGuardSessionKey(sessionKey)) return false;
  const idx = sessionKey.indexOf(":guard");
  if (idx === -1) return false;
  const parentKey = sessionKey.slice(0, idx);
  return registeredGuardParents.has(parentKey);
}

/** Clear registry entry when a guard session ends (housekeeping). */
export function deregisterGuardSession(sessionKey: string): void {
  const idx = sessionKey.indexOf(":guard");
  if (idx !== -1) registeredGuardParents.delete(sessionKey.slice(0, idx));
}

/**
 * Build a placeholder message to insert into the main (cloud-visible) session history
 * when a message is redirected to the guard subsession.
 *
 * This ensures the cloud model never sees the actual sensitive content,
 * but knows that something was handled privately.
 */
export function buildMainSessionPlaceholder(level: SensitivityLevel, reason?: string, timestamp?: number): string {
  const emoji = level === "S3" ? "🔒" : "🔑";
  const levelLabel = level === "S3" ? "Private" : "Sensitive";
  const reasonSuffix = reason ? ` (${reason})` : "";
  const tsSuffix = timestamp ? ` [ts=${new Date(timestamp).toISOString()}]` : "";
  return `${emoji} [${levelLabel} message — processed locally${reasonSuffix}]${tsSuffix}`;
}

const BUILTIN_LOCAL_PROVIDERS = [
  "ollama", "llama.cpp", "localai", "llamafile", "lmstudio",
  "vllm", "mlx", "sglang", "tgi", "koboldcpp", "tabbyapi", "nitro",
];

/**
 * Validate that a model reference is local-only (not a cloud provider).
 * Used to enforce the constraint that guard sessions only use local models.
 *
 * Checks against built-in list + any extra providers from config.localProviders.
 */
export function isLocalProvider(provider: string, extraProviders?: string[]): boolean {
  const lower = provider.toLowerCase();
  if (BUILTIN_LOCAL_PROVIDERS.includes(lower)) return true;
  if (extraProviders?.some((p) => p.toLowerCase() === lower)) return true;
  return false;
}
