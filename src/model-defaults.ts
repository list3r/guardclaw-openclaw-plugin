/**
 * GuardClaw Model Defaults
 *
 * ── Single source of truth for all default/fallback model references ──
 *
 * These values are used as last-resort fallbacks when no config is loaded
 * (e.g. guardclaw.json is missing or corrupt).  The live values are always
 * read from ~/.openclaw/guardclaw.json at runtime — change them there first.
 *
 * When you change the inference stack, update this file to keep fallbacks in
 * sync.  Every hardcoded model string in the codebase imports from here.
 *
 * Design principle: defaults reference PROVIDER ALIASES, not specific model
 * strings.  Swap the active model in your OpenClaw provider config — no code
 * changes required.  Only the local classifier needs a model name because it
 * calls Ollama directly via HTTP (outside the OpenClaw provider system).
 *
 * Current stack:
 *   Classifier  → llama3.2:3b  @ localhost:11434  (fast local, direct HTTP)
 *   Guard agent → provider set in guardclaw.json   (no default — must be configured)
 *
 * NOTE: There is intentionally NO default provider for the guard agent.
 * GuardClaw runs on many machines in many networks. "ollama-remote" is the
 * right choice on one box; on another it might be "ollama-120", "vllm-gpu",
 * or "financial-llm". Users set privacy.guardAgent.provider in guardclaw.json
 * to match their local inference stack. GuardClaw warns at startup if unset.
 */

// ── Local classifier (runs on every message — must be fast) ──────────────

/**
 * Ollama model used for S1/S2/S3 classification and PII extraction.
 * This is a direct HTTP call to Ollama — the model must be pulled on the
 * classifier host.  To change it, update `localModel.model` in guardclaw.json.
 */
export const DEFAULT_LOCAL_CLASSIFIER_MODEL = "llama3.2:3b";

/** Ollama endpoint for the local classifier. */
export const DEFAULT_LOCAL_CLASSIFIER_ENDPOINT = "http://localhost:11434";

/** Provider alias for the local classifier. */
export const DEFAULT_LOCAL_CLASSIFIER_PROVIDER = "ollama";

// ── Guard agent ─────────────────────────────────────────────────────────────
//
// No constants here. The guard agent provider is configured by the user in
// guardclaw.json (privacy.guardAgent.provider). GuardClaw intentionally ships
// with no default — the right provider depends on the deployment.
//
// See src/guard-agent.ts and the GuardClaw README for configuration examples.
