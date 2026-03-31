/**
 * GuardClaw Behavioral Attestation Scorer
 *
 * Scores how suspicious a session's recent tool-call sequence looks before
 * allowing a secret operation to proceed.
 *
 * Current implementation: rule-based heuristics.
 * Future: replace or augment score() with a trained classifier once the
 *         behavioral log (guardclaw-behavior.jsonl) has enough labeled data.
 *
 * Controlled by guardclaw.json → privacy.behavioralAttestation:
 *   enabled        – false: nothing runs (default)
 *   logOnly        – true: score is computed and logged but never blocks (default)
 *   windowSize     – how many recent tool calls to consider (default: 10)
 *   blockThreshold – suspicion score (0–1) at which to block (default: 0.8)
 *                    only active when logOnly is false
 */

import type { BehavioralEvent } from "./behavioral-log.js";

// ── Config type (mirrors config-schema.ts) ─────────────────────────────────

export type BehavioralAttestationConfig = {
  enabled?: boolean;
  logOnly?: boolean;
  windowSize?: number;
  blockThreshold?: number;
};

// ── Score result ───────────────────────────────────────────────────────────

export type AttestationResult = {
  /** 0 = benign, 1 = maximally suspicious */
  score: number;
  /** Human-readable signals that contributed to the score */
  signals: string[];
  /** Whether this should block the operation (false if logOnly) */
  shouldBlock: boolean;
};

// ── Rule-based scorer ──────────────────────────────────────────────────────

/**
 * Score the recent event window before a secret operation.
 *
 * Signals (additive, capped at 1.0):
 *   +0.35  Bulk file reads  — ≥4 file_read events in window (injection pre-stage)
 *   +0.25  Rapid web fetches — ≥3 web_fetch events in window (data staging)
 *   +0.20  Shell→secret sequence — shell call immediately before secret request
 *   +0.15  High sensitivity spike — ≥2 S3 events in window
 *   +0.10  Tool category churn — ≥5 different categories in window (erratic)
 *   -0.20  Consistent session — all events same category (focused task)
 *   -0.10  Single event window — only one event, low context for suspicion
 */
export function score(events: BehavioralEvent[]): Pick<AttestationResult, "score" | "signals"> {
  if (events.length === 0) return { score: 0, signals: ["no prior tool calls — no behavioral context"] };

  let s = 0;
  const signals: string[] = [];

  const categories = events.map((e) => e.category);
  const uniqueCategories = new Set(categories);
  const fileReads = events.filter((e) => e.category === "file_read").length;
  const webFetches = events.filter((e) => e.category === "web_fetch").length;
  const s3Events = events.filter((e) => e.sensitivity === "S3").length;
  const lastCategory = categories[categories.length - 1];

  // Bulk file reads preceding a secret op — classic pre-exfil staging
  if (fileReads >= 4) {
    s += 0.35;
    signals.push(`${fileReads} file reads in last ${events.length} calls (bulk read pattern)`);
  } else if (fileReads >= 2) {
    s += 0.10;
    signals.push(`${fileReads} file reads in last ${events.length} calls`);
  }

  // Rapid web fetches — could be staging data before exfil
  if (webFetches >= 3) {
    s += 0.25;
    signals.push(`${webFetches} web fetches in last ${events.length} calls`);
  } else if (webFetches >= 2) {
    s += 0.10;
    signals.push(`${webFetches} web fetches in last ${events.length} calls`);
  }

  // Shell call immediately before secret request
  if (lastCategory === "shell") {
    s += 0.20;
    signals.push("shell call immediately before secret operation");
  }

  // High-sensitivity events in window
  if (s3Events >= 2) {
    s += 0.15;
    signals.push(`${s3Events} S3-sensitivity events in window`);
  } else if (s3Events === 1) {
    s += 0.05;
    signals.push("1 S3-sensitivity event in window");
  }

  // Tool category churn — erratic behaviour
  if (uniqueCategories.size >= 5) {
    s += 0.10;
    signals.push(`${uniqueCategories.size} different tool categories (erratic pattern)`);
  }

  // Negative signals — looks like a focused, consistent task
  if (uniqueCategories.size === 1) {
    s -= 0.20;
    signals.push(`consistent task — all ${events.length} calls are ${categories[0]}`);
  }

  if (events.length === 1) {
    s -= 0.10;
    signals.push("minimal context — only 1 prior tool call");
  }

  return {
    score: Math.max(0, Math.min(1, s)),
    signals,
  };
}

// ── Main entry point ───────────────────────────────────────────────────────

/**
 * Evaluate a session's behavioral context before allowing a secret operation.
 *
 * @param events   Recent tool-call events for this session (from behavioral-log)
 * @param cfg      Config from guardclaw.json → privacy.behavioralAttestation
 * @returns        AttestationResult with score, signals, and shouldBlock
 */
export function attest(
  events: BehavioralEvent[],
  cfg: BehavioralAttestationConfig,
): AttestationResult {
  const { score: s, signals } = score(events);
  const threshold = cfg.blockThreshold ?? 0.8;
  const logOnly = cfg.logOnly !== false; // default true

  return {
    score: s,
    signals,
    // Never block when logOnly (data collection phase)
    shouldBlock: !logOnly && s >= threshold,
  };
}
