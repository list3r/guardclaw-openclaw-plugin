/**
 * GuardClaw Taint Store
 *
 * Value-based taint tracking for secret propagation across tool results.
 *
 * When a secret value is sourced from a secrets mount (/run/secrets/, /var/run/secrets/)
 * or detected in an S2/S3 tool result, the exact value is registered as "tainted".
 * Every subsequent tool result in the session is scanned for tainted values, and any
 * occurrence is redacted before it reaches the cloud LLM.
 *
 * Architecture mirrors secret-manager.ts: per-session in-memory Sets, cleared on
 * session_end, with a pending-taint mechanism bridging before_tool_call →
 * tool_result_persist across the hook boundary.
 *
 * Toggle: privacy.taintTracking.enabled (default: true)
 */

// ── Constants ─────────────────────────────────────────────────────────────────

/**
 * Values shorter than this are too common to track safely (false-positive risk).
 * Set to 4 to match secret-manager.ts MIN_SECRET_LENGTH (GCF-013).
 * Accepts slightly higher false-positive risk from common short values in
 * exchange for consistent coverage with the Keychain tracking path.
 */
const MIN_TAINT_LENGTH = 4;

/** Hard cap on tainted values per session to prevent memory exhaustion. */
const MAX_TAINTS_PER_SESSION = 200;

/**
 * Fraction of the store to evict when the cap is hit. Batch eviction avoids
 * the pathological case where every new registration triggers an individual
 * eviction + log + Map iteration. With 25% batch, hitting the cap once frees
 * 50 slots — the next 50 registrations are free of eviction overhead.
 */
const EVICTION_BATCH_FRACTION = 0.25;

// ── Types ─────────────────────────────────────────────────────────────────────

export type TaintSensitivity = "S2" | "S3";

/** Free-form label describing where the tainted value came from. */
export type TaintSource = string;

type PendingTaint = {
  source: TaintSource;
  sensitivity: TaintSensitivity;
};

// ── Per-session state ─────────────────────────────────────────────────────────

/** sessionKey → Set of tainted literal values (insertion-ordered for LRU eviction). */
const _taints = new Map<string, Set<string>>();

/** sessionKey → value → "S2|S3:source" label (for stats / debug). */
const _sources = new Map<string, Map<string, string>>();

/**
 * GCF-014: Pending taint registrations set in before_tool_call and consumed in
 * tool_result_persist so the tool result content can be registered.
 * Changed from single-slot Map<string, PendingTaint> to per-session queue
 * Map<string, PendingTaint[]> so concurrent tool calls each get tainted.
 * markPendingTaint pushes; consumePendingTaint shifts (FIFO).
 */
const _pending = new Map<string, PendingTaint[]>();

// ── Registration ──────────────────────────────────────────────────────────────

/**
 * Register a literal value as tainted for this session.
 *
 * GCF-012: When the per-session cap is hit, uses LRU eviction instead of
 * silent drop. Secrets-mount taints (source starts with "secrets-file:", higher-trust)
 * are never evicted; only S2/S3 tool-result taints are candidates for eviction.
 * Logs a WARN when eviction occurs so operators are alerted.
 *
 * Deduplicates automatically — registering the same value twice is a no-op.
 */
export function registerTaint(
  sessionKey: string,
  value: string,
  source: TaintSource,
  sensitivity: TaintSensitivity,
  minLength = MIN_TAINT_LENGTH,
): void {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length < minLength) return;

  let set = _taints.get(sessionKey);
  if (!set) {
    set = new Set();
    _taints.set(sessionKey, set);
  }

  if (set.has(trimmed)) return; // dedup

  if (set.size >= MAX_TAINTS_PER_SESSION) {
    // GCF-012: Batch LRU eviction — evict EVICTION_BATCH_FRACTION of evictable entries
    // at once to avoid per-registration overhead when the store is persistently full.
    const srcMap = _sources.get(sessionKey);
    const batchTarget = Math.max(1, Math.floor(MAX_TAINTS_PER_SESSION * EVICTION_BATCH_FRACTION));
    let evictedCount = 0;
    if (srcMap) {
      const candidates: string[] = [];
      for (const [candidate, label] of srcMap) {
        if (!label.includes(":secrets-file:")) {
          candidates.push(candidate);
          if (candidates.length >= batchTarget) break;
        }
      }
      for (const candidate of candidates) {
        set.delete(candidate);
        srcMap.delete(candidate);
        evictedCount++;
      }
    }
    if (evictedCount > 0) {
      console.warn(
        `[GuardClaw:taint] Cap hit (session=${sessionKey}): batch-evicted ${evictedCount} oldest evictable taints (cap=${MAX_TAINTS_PER_SESSION}, remaining=${set.size})`,
      );
    } else {
      console.warn(
        `[GuardClaw:taint] Cap hit (session=${sessionKey}): all ${MAX_TAINTS_PER_SESSION} slots are secrets-mount protected — dropping new entry from source="${source}"`,
      );
      return;
    }
  }

  set.add(trimmed);

  let srcMap = _sources.get(sessionKey);
  if (!srcMap) {
    srcMap = new Map();
    _sources.set(sessionKey, srcMap);
  }
  srcMap.set(trimmed, `${sensitivity}:${source}`);
}

// ── Detection / Redaction ─────────────────────────────────────────────────────

/**
 * Returns true if `text` contains any tainted value for this session.
 */
export function isTainted(sessionKey: string, text: string): boolean {
  const set = _taints.get(sessionKey);
  if (!set || set.size === 0) return false;
  for (const taint of set) {
    if (text.includes(taint)) return true;
  }
  return false;
}

/**
 * Replace every occurrence of every tainted value in `text` with [REDACTED:TAINT].
 *
 * Uses split/join instead of RegExp to avoid escaping issues with special characters
 * that are common in passwords, tokens, and API keys (same pattern as secret-manager.ts).
 */
export function redactTainted(sessionKey: string, text: string): string {
  const set = _taints.get(sessionKey);
  if (!set || set.size === 0) return text;
  let result = text;
  for (const taint of set) {
    if (result.includes(taint)) {
      result = result.split(taint).join("[REDACTED:TAINT]");
    }
  }
  return result;
}

/**
 * Returns true if any tainted values are registered for this session.
 */
export function hasTaints(sessionKey: string): boolean {
  const set = _taints.get(sessionKey);
  return set != null && set.size > 0;
}

// ── Pending taint (before_tool_call → tool_result_persist bridge) ─────────────

/**
 * Mark that the NEXT tool result for this session should have its content
 * registered as tainted values. Called from before_tool_call when a
 * secrets-mount path is detected in the tool parameters.
 *
 * GCF-014: Pushes onto a per-session queue (instead of overwriting a single slot)
 * so concurrent secrets-mount reads each get their own pending-taint entry.
 */
export function markPendingTaint(
  sessionKey: string,
  source: TaintSource,
  sensitivity: TaintSensitivity,
): void {
  const queue = _pending.get(sessionKey) ?? [];
  queue.push({ source, sensitivity });
  _pending.set(sessionKey, queue);
}

/**
 * Check and clear the oldest pending taint entry for a session (FIFO).
 * Returns the pending taint descriptor if one was queued; null otherwise.
 * Must be called in tool_result_persist to consume the entry before registering values.
 *
 * GCF-014: Shifts from the queue so concurrent tool calls are served in order.
 */
export function consumePendingTaint(sessionKey: string): PendingTaint | null {
  const queue = _pending.get(sessionKey);
  if (!queue || queue.length === 0) return null;
  const entry = queue.shift()!;
  if (queue.length === 0) _pending.delete(sessionKey);
  return entry;
}

// ── Session lifecycle ─────────────────────────────────────────────────────────

/**
 * Clear all tainted values and pending taint state for a session.
 * Must be called when a session ends to prevent indefinite memory retention.
 */
export function clearTaintSession(sessionKey: string): void {
  _taints.delete(sessionKey);
  _sources.delete(sessionKey);
  _pending.delete(sessionKey);
}

/**
 * Return stats about the taint store for a session (for logging/dashboard).
 */
export function getTaintStats(sessionKey: string): { count: number; sources: string[] } {
  const set = _taints.get(sessionKey) ?? new Set<string>();
  const srcMap = _sources.get(sessionKey) ?? new Map<string, string>();
  return {
    count: set.size,
    sources: [...new Set(srcMap.values())],
  };
}

// ── Value extraction ──────────────────────────────────────────────────────────

/**
 * Extract individual taintable values from tool result content.
 *
 * Handles:
 *   - Single-line content (the whole trimmed line is the secret, e.g. a password file)
 *   - KEY=VALUE format (env-var style; the VALUE is extracted and tracked)
 *   - Multi-line secrets files (one value per non-comment line)
 *
 * Returns a deduplicated list of values that meet the minimum length threshold.
 */
export function extractTaintValues(
  content: string,
  minLength = MIN_TAINT_LENGTH,
): string[] {
  const collected = new Set<string>();
  const trimmedFull = content.trim();

  if (!trimmedFull) return [];

  // Single-line: the whole value is the secret (common for /run/secrets/* files)
  if (!trimmedFull.includes("\n")) {
    if (trimmedFull.length >= minLength && trimmedFull.length <= 8192) {
      collected.add(trimmedFull);
    }
    return [...collected];
  }

  // Multi-line: parse line by line
  for (const rawLine of trimmedFull.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("//")) continue;

    // KEY=VALUE format (env-var / .env / secrets config files)
    // Supports: KEY=value, export KEY=value, KEY="value", KEY='value'
    const envMatch = line.match(/^(?:export\s+)?[A-Z_][A-Z0-9_]*\s*=\s*(.+)$/i);
    if (envMatch) {
      const val = envMatch[1].trim().replace(/^["']|["']$/g, "");
      if (val.length >= minLength) collected.add(val);
      continue;
    }

    // Bare value line (each line is an independent secret value)
    if (line.length >= minLength && line.length <= 8192) {
      collected.add(line);
    }
  }

  // Also register the full multi-line content as a single taint entry
  // (catches tools that echo the entire file content in a single string match)
  if (trimmedFull.length >= minLength && trimmedFull.length <= 8192) {
    collected.add(trimmedFull);
  }

  return [...collected];
}

// ── Path detection ────────────────────────────────────────────────────────────

/**
 * Returns true if the given path points to a Linux secrets mount.
 * Covers both the standard Docker secrets path (/run/secrets/) and the
 * Kubernetes variant (/var/run/secrets/).
 */
export function isSecretsMountPath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/");
  return (
    normalized.startsWith("/run/secrets/") ||
    normalized.startsWith("/var/run/secrets/")
  );
}
