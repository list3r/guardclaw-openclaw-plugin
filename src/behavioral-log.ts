/**
 * GuardClaw Behavioral Attestation Log
 *
 * Appends a JSONL record for every tool call that passes through the pipeline.
 * Records are used to:
 *   1. Build training data for the behavioral attestation scorer (future)
 *   2. Provide context to the intent verifier when an agent requests a secret op
 *
 * When a secret operation is requested in a session, all preceding events for
 * that session get their `secretOpMs` field back-filled — recording how many
 * milliseconds before the secret request each event occurred. This gives
 * automatic labeling: sequences with secretOpMs set are "pre-secret" context.
 *
 * Log location: ~/.openclaw/guardclaw-behavior.jsonl
 * Format: one JSON object per line, newline-delimited
 */

import { appendFile, readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";

// ── Types ──────────────────────────────────────────────────────────────────

export type ToolCategory =
  | "shell"       // exec, bash, run_command, etc.
  | "file_read"   // read_file, cat, head, etc.
  | "file_write"  // write_file, edit, etc.
  | "web_fetch"   // web_fetch, http_get, curl, etc.
  | "memory"      // memory_get, memory_search, etc.
  | "api_call"    // generic API calls
  | "message"     // send_message, post, etc.
  | "search"      // web_search, grep, glob
  | "other";

export type BehavioralEvent = {
  /** ISO timestamp */
  ts: string;
  /** Full session key e.g. "agent:main:cron:abc123" */
  session: string;
  /** Agent ID extracted from session key e.g. "main" */
  agent: string;
  /** Sequence number within this session (1-based) */
  seq: number;
  /** Raw tool name as reported by the platform */
  tool: string;
  /** Bucketed category for analysis */
  category: ToolCategory;
  /** Sensitivity level GuardClaw assigned to this turn (if known) */
  sensitivity: "S1" | "S2" | "S3" | null;
  /** FNV-32 hash of tool params — for dedup/pattern matching without storing PII */
  paramsHash: string;
  /** ms before the next secret operation in this session (null = no secret op yet) */
  secretOpMs: number | null;
};

// ── Constants ──────────────────────────────────────────────────────────────

const HOME = process.env.HOME ?? process.env.USERPROFILE ?? "/tmp";
const LOG_PATH = join(HOME, ".openclaw", "guardclaw-behavior.jsonl");

// In-memory sequence counters and pending events per session.
// Cleared when a session ends.
const _seqCounters = new Map<string, number>();
const _pendingEvents = new Map<string, BehavioralEvent[]>();

// ── Helpers ────────────────────────────────────────────────────────────────

/** Deterministic FNV-32a hash of a string — fast, non-cryptographic. */
function fnv32a(str: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

/** Map a raw tool name to a broad category. */
export function categoriseTool(toolName: string): ToolCategory {
  const t = toolName.toLowerCase();
  if (/exec|bash|shell|run_command|system|cmd/.test(t)) return "shell";
  if (/read_file|read|cat|head|tail|open_file|get_file/.test(t)) return "file_read";
  if (/write_file|write|edit|patch|create_file|append/.test(t)) return "file_write";
  if (/web_fetch|http|curl|fetch|request|download/.test(t)) return "web_fetch";
  if (/memory|remember|recall|retrieve|store/.test(t)) return "memory";
  if (/search|grep|glob|find|query/.test(t)) return "search";
  if (/message|send|post|notify|discord|slack/.test(t)) return "message";
  if (/api|call|invoke|rpc/.test(t)) return "api_call";
  return "other";
}

/** Extract agent ID from a session key like "agent:main:cron:abc". */
function agentFromSession(sessionKey: string): string {
  const parts = sessionKey.split(":");
  // "agent:main:cron:uuid" → "main"
  if (parts[0] === "agent" && parts.length >= 2) return parts[1];
  return parts[0] ?? "unknown";
}

// ── Core API ───────────────────────────────────────────────────────────────

/**
 * Record a tool call event.
 * Fire-and-forget — errors are swallowed to avoid disrupting the pipeline.
 */
export function logToolEvent(
  sessionKey: string,
  toolName: string,
  params: Record<string, unknown>,
  sensitivity: "S1" | "S2" | "S3" | null,
): void {
  try {
    const seq = (_seqCounters.get(sessionKey) ?? 0) + 1;
    _seqCounters.set(sessionKey, seq);

    const event: BehavioralEvent = {
      ts: new Date().toISOString(),
      session: sessionKey,
      agent: agentFromSession(sessionKey),
      seq,
      tool: toolName,
      category: categoriseTool(toolName),
      sensitivity,
      paramsHash: fnv32a(JSON.stringify(params)),
      secretOpMs: null,
    };

    // Buffer in memory for back-filling
    const pending = _pendingEvents.get(sessionKey) ?? [];
    pending.push(event);
    _pendingEvents.set(sessionKey, pending);

    // Append to disk immediately (best-effort)
    appendFile(LOG_PATH, JSON.stringify(event) + "\n", { encoding: "utf-8", mode: 0o600 }).catch(() => {});
  } catch {
    // Never disrupt the pipeline
  }
}

/**
 * Called when a secret operation is requested in a session.
 * Back-fills secretOpMs on all in-memory events for this session that
 * don't already have it set, then rewrites those lines in the JSONL file.
 */
export function markSecretOperation(sessionKey: string): void {
  const pending = _pendingEvents.get(sessionKey);
  if (!pending || pending.length === 0) return;

  const now = Date.now();
  const updated: BehavioralEvent[] = [];

  for (const ev of pending) {
    if (ev.secretOpMs === null) {
      const msAgo = now - new Date(ev.ts).getTime();
      ev.secretOpMs = msAgo;
      updated.push(ev);
    }
  }

  if (updated.length === 0) return;

  // Rewrite affected lines in the JSONL file
  _rewriteSecretOpMs(updated).catch(() => {});
}

/**
 * Clear in-memory state for a session (call on session_end).
 */
export function clearBehavioralSession(sessionKey: string): void {
  _seqCounters.delete(sessionKey);
  _pendingEvents.delete(sessionKey);
}

/**
 * Return the last N behavioral events for a session (in-memory, no disk read).
 * Used by the attestation scorer to get recent context.
 */
export function getRecentEvents(sessionKey: string, limit = 10): BehavioralEvent[] {
  const pending = _pendingEvents.get(sessionKey) ?? [];
  return pending.slice(-limit);
}

// ── JSONL back-fill ────────────────────────────────────────────────────────

/**
 * Read the JSONL file, update matching events' secretOpMs, write back.
 * Uses a tmp-then-rename pattern for atomicity.
 * This is best-effort — called async, errors swallowed.
 */
async function _rewriteSecretOpMs(updated: BehavioralEvent[]): Promise<void> {
  try {
    // Build a lookup: session+seq → secretOpMs
    const lookup = new Map<string, number>();
    for (const ev of updated) {
      lookup.set(`${ev.session}:${ev.seq}`, ev.secretOpMs!);
    }

    const raw = await readFile(LOG_PATH, "utf-8").catch(() => "");
    if (!raw.trim()) return;

    const lines = raw.split("\n");
    const out: string[] = [];

    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const obj = JSON.parse(line) as BehavioralEvent;
        const key = `${obj.session}:${obj.seq}`;
        if (lookup.has(key) && obj.secretOpMs === null) {
          obj.secretOpMs = lookup.get(key)!;
        }
        out.push(JSON.stringify(obj));
      } catch {
        out.push(line); // keep malformed lines as-is
      }
    }

    const tmp = LOG_PATH + ".tmp";
    await writeFile(tmp, out.join("\n") + "\n", { encoding: "utf-8", mode: 0o600 });
    await rename(tmp, LOG_PATH);
  } catch {
    // Best-effort
  }
}
