/**
 * GuardClaw Budget Guard
 *
 * Tracks cumulative cloud token costs (daily / monthly) and enforces caps.
 *
 * Key design decisions:
 *   - Maintains its own lightweight cost counters, independent of token-stats.
 *     token-stats is analytics-focused (72-hour hourly window); budget-guard
 *     is enforcement-focused (daily + rolling 35-day window for monthly).
 *   - Atomic persistence to ~/.openclaw/guardclaw-budget.json.
 *   - recordCost() is fire-and-forget (async persist doesn't block hot path).
 *   - checkBudget() is synchronous — safe to call in before_model_resolve.
 *
 * Actions:
 *   warn         → log + webhook, request continues normally
 *   pause_cloud  → redirect this request to local model until daily limit resets
 *   block        → throw error, request is refused
 */

import { readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";

// ── Types ──

export type BudgetAction = "warn" | "pause_cloud" | "block";

export type BudgetConfig = {
  /** Enable budget enforcement. Default: false */
  enabled?: boolean;
  /** Daily spend cap in USD. Resets at midnight UTC. */
  dailyCap?: number;
  /** Monthly spend cap in USD. Resets on the 1st of each month UTC. */
  monthlyCap?: number;
  /** Action when cap is reached. Default: "warn" */
  action?: BudgetAction;
  /** Fraction of cap at which to fire a warning webhook (0–1). Default: 0.8 */
  warnAt?: number;
};

export type BudgetStatus = {
  ok: boolean;
  warning: boolean;
  exceeded: boolean;
  dailyCost: number;
  monthlyCost: number;
  dailyCap?: number;
  monthlyCap?: number;
  action: BudgetAction;
};

type BudgetData = {
  /** "YYYY-MM-DD" → cumulative USD for that day */
  dailyCosts: Record<string, number>;
  /** "YYYY-MM" → cumulative USD for that month */
  monthlyCosts: Record<string, number>;
  lastUpdated: string;
};

// ── Persistence ──

const HOME = process.env.HOME ?? process.env.USERPROFILE ?? "/tmp";
const BUDGET_PATH = join(HOME, ".openclaw", "guardclaw-budget.json");

let _data: BudgetData = { dailyCosts: {}, monthlyCosts: {}, lastUpdated: "" };

/** Load persisted budget data from disk. Non-fatal — starts fresh on error. */
export async function loadBudgetData(): Promise<void> {
  try {
    const raw = await readFile(BUDGET_PATH, "utf-8");
    _data = JSON.parse(raw) as BudgetData;

    // Prune daily entries older than 35 days
    const cutoff = new Date();
    cutoff.setUTCDate(cutoff.getUTCDate() - 35);
    for (const key of Object.keys(_data.dailyCosts)) {
      if (new Date(key) < cutoff) delete _data.dailyCosts[key];
    }

    // Prune monthly entries older than 13 months
    const monthCutoff = new Date();
    monthCutoff.setUTCMonth(monthCutoff.getUTCMonth() - 13);
    for (const key of Object.keys(_data.monthlyCosts)) {
      const [y, m] = key.split("-").map(Number);
      if (new Date(Date.UTC(y, m - 1)) < monthCutoff) delete _data.monthlyCosts[key];
    }
  } catch {
    // File absent or corrupt — normal on first run
  }
}

async function persistBudget(): Promise<void> {
  _data.lastUpdated = new Date().toISOString();
  const tmp = BUDGET_PATH + ".tmp";
  try {
    await writeFile(tmp, JSON.stringify(_data, null, 2), { encoding: "utf-8", mode: 0o600 });
    await rename(tmp, BUDGET_PATH);
  } catch { /* best-effort */ }
}

// ── Cost calculation ──

/**
 * Calculate request cost in USD.
 * Mirrors token-stats pricing lookup: exact match → substring match → default.
 */
export function calculateCost(
  model: string,
  usage: { input?: number; output?: number },
  pricing: Record<string, { inputPer1M?: number; outputPer1M?: number }>,
): number {
  const input = usage.input ?? 0;
  const output = usage.output ?? 0;
  if (input === 0 && output === 0) return 0;

  const modelLower = model.toLowerCase();
  let p: { inputPer1M?: number; outputPer1M?: number } | undefined;

  // Exact match
  p = pricing[model] ?? pricing[modelLower];

  // Substring match (handles "openai/gpt-4o" → "gpt-4o" lookup)
  if (!p) {
    for (const [key, val] of Object.entries(pricing)) {
      if (modelLower.includes(key.toLowerCase()) || key.toLowerCase().includes(modelLower)) {
        p = val;
        break;
      }
    }
  }

  const inputRate = p?.inputPer1M ?? 3;
  const outputRate = p?.outputPer1M ?? 15;
  return (input * inputRate + output * outputRate) / 1_000_000;
}

// ── Runtime API ──

function todayKey(): string {
  return new Date().toISOString().slice(0, 10); // "2026-03-27"
}

function thisMonthKey(): string {
  return new Date().toISOString().slice(0, 7); // "2026-03"
}

/** Record a cost event. Fire-and-forget persist — never blocks. */
export function recordCost(cost: number): void {
  if (cost <= 0) return;
  const day = todayKey();
  const month = thisMonthKey();
  _data.dailyCosts[day] = (_data.dailyCosts[day] ?? 0) + cost;
  _data.monthlyCosts[month] = (_data.monthlyCosts[month] ?? 0) + cost;
  persistBudget().catch(() => {});
}

export function getDailyCost(date = todayKey()): number {
  return _data.dailyCosts[date] ?? 0;
}

export function getMonthlyCost(month = thisMonthKey()): number {
  return _data.monthlyCosts[month] ?? 0;
}

/**
 * Check current spend against configured caps.
 * Synchronous — safe to call on every before_model_resolve.
 */
export function checkBudget(config: BudgetConfig): BudgetStatus {
  const action = config.action ?? "warn";
  const warnAt = config.warnAt ?? 0.8;
  const dailyCost = getDailyCost();
  const monthlyCost = getMonthlyCost();

  let exceeded = false;
  let warning = false;

  if (config.dailyCap && config.dailyCap > 0) {
    if (dailyCost >= config.dailyCap) exceeded = true;
    else if (dailyCost >= config.dailyCap * warnAt) warning = true;
  }

  if (!exceeded && config.monthlyCap && config.monthlyCap > 0) {
    if (monthlyCost >= config.monthlyCap) exceeded = true;
    else if (!warning && monthlyCost >= config.monthlyCap * warnAt) warning = true;
  }

  return {
    ok: !exceeded && !warning,
    warning,
    exceeded,
    dailyCost,
    monthlyCost,
    dailyCap: config.dailyCap,
    monthlyCap: config.monthlyCap,
    action,
  };
}

/** Raw data snapshot for dashboard API. */
export function getBudgetSnapshot(): BudgetData {
  return _data;
}
