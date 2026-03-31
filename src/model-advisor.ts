/**
 * GuardClaw Model Advisor
 *
 * Periodically checks for better/cheaper models across three dimensions:
 *
 *   1. OpenRouter sweep   — compare current tier targets against the full
 *                           model catalog by blended token cost. Suggests
 *                           swaps when a model is ≥ minSavingsPercent cheaper
 *                           and passes the capability filter for that tier.
 *
 *   2. LLMFit scan        — runs `llmfit recommend --json --limit 10` to find
 *                           models that fit the local hardware better than the
 *                           current judge or guard-agent model. Checks disk
 *                           space before suggesting a pull.
 *
 *   3. DeBERTa watch      — polls HuggingFace for newer prompt-injection models
 *                           from the protectai namespace. New versions are new
 *                           repo IDs (e.g. v3), not branches.
 *
 * Optionally benchmarks candidates before suggesting a swap:
 *   - Sends the judge prompt + fixed test messages to the candidate model
 *   - Measures JSON parse success rate + average latency
 *   - Only creates a suggestion if the candidate ≥ 5% better on both metrics
 *
 * Suggestions persist to ~/.openclaw/guardclaw-suggestions.json.
 * Schedule default: every 2 weeks; checks at startup if overdue.
 */

import { readFile, writeFile, rename, statfs } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { callChatCompletion } from "./local-model.js";
import { getLiveConfig, updateLiveConfig } from "./live-config.js";
import { triggerDebertaReload } from "./injection/deberta.js";
import { DEFAULT_JUDGE_PROMPT } from "./routers/token-saver.js";
import type { EdgeProviderType, ModelAdvisorConfig, ModelSuggestion, SuggestionType, SuggestionStatus, BenchmarkResult } from "./types.js";

const execFileAsync = promisify(execFile);

// ── Types ──

type Tier = "SIMPLE" | "MEDIUM" | "COMPLEX" | "REASONING";

export type { ModelAdvisorConfig, ModelSuggestion, SuggestionType, SuggestionStatus, BenchmarkResult };

type AdvisorData = {
  lastCheckedAt: string | null;
  suggestions: ModelSuggestion[];
};

// ── Constants ──

const HOME = process.env.HOME ?? process.env.USERPROFILE ?? "/tmp";
const SUGGESTIONS_PATH = join(HOME, ".openclaw", "guardclaw-suggestions.json");
const MS_PER_WEEK = 7 * 24 * 60 * 60 * 1000;
const OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models";
const HF_PROTECTAI_URL = "https://huggingface.co/api/models?author=protectai&search=prompt-injection";
const CURRENT_DEBERTA_MODEL = "protectai/deberta-v3-base-prompt-injection-v2";
const CURRENT_DEBERTA_VERSION = 2;
const FETCH_TIMEOUT_MS = 15_000;

// Keywords that identify a model as suitable for each tier's capability level.
// A model with ANY keyword from COMPLEX is not suitable for SIMPLE/MEDIUM.
// A model with ANY keyword from REASONING is only suitable for REASONING.
const REASONING_KEYWORDS = ["thinking", "reasoning", "qwq", "deepseek-r1", "o1", "o3", "r1-", "r1:"];
const COMPLEX_KEYWORDS = ["opus", "sonnet", "large", "pro", "plus", "70b", "72b", "34b", "65b", "gemini-2.5"];
const SMALL_KEYWORDS = ["mini", "haiku", "flash", "lite", "nano", "small", "tiny", "3b", "1b", "0.5b"];

const BENCHMARK_PROMPTS: Array<{ prompt: string; expectedTier: Tier }> = [
  { prompt: "What is the capital of France?", expectedTier: "SIMPLE" },
  { prompt: "Write a Python function that returns the Fibonacci sequence up to n.", expectedTier: "MEDIUM" },
  { prompt: "Design a microservices architecture for a hospital management system with departments, doctors, patients, appointments, and billing. Describe the key services and their interactions.", expectedTier: "COMPLEX" },
  { prompt: "Prove by mathematical induction that the sum of the first n natural numbers equals n(n+1)/2.", expectedTier: "REASONING" },
];

// ── Singleton state ──

let _data: AdvisorData = { lastCheckedAt: null, suggestions: [] };
let _config: ModelAdvisorConfig = {};
let _openrouterApiKey = "";
let _logger: { info: (m: string) => void; warn: (m: string) => void; error: (m: string) => void } = console;
let _scheduleTimer: ReturnType<typeof setInterval> | null = null;
let _running = false;

// ── Persistence ──

async function loadAdvisorData(): Promise<void> {
  try {
    const raw = await readFile(SUGGESTIONS_PATH, "utf-8");
    _data = JSON.parse(raw) as AdvisorData;
    // Prune accepted/dismissed older than 60 days
    const cutoff = Date.now() - 60 * 24 * 60 * 60 * 1000;
    _data.suggestions = _data.suggestions.filter(
      (s) => s.status === "pending" || new Date(s.createdAt).getTime() > cutoff,
    );
  } catch {
    // File absent — normal on first run
  }
}

async function saveAdvisorData(): Promise<void> {
  const tmp = SUGGESTIONS_PATH + ".tmp";
  try {
    await writeFile(tmp, JSON.stringify(_data, null, 2), { encoding: "utf-8", mode: 0o600 });
    await rename(tmp, SUGGESTIONS_PATH);
  } catch { /* best-effort */ }
}

function makeSuggestionId(type: string, value: string): string {
  return createHash("sha256").update(`${type}:${value}`).digest("hex").slice(0, 12);
}

function hasSuggestion(id: string): boolean {
  return _data.suggestions.some((s) => s.id === id && s.status === "pending");
}

// ── Disk space check ──

/**
 * Returns free disk space in GB for the path that will store models.
 * Checks $OLLAMA_MODELS first, then ~/.ollama, then home directory.
 */
async function getFreeDiskGb(checkPath?: string): Promise<number> {
  const paths = [
    checkPath,
    process.env.OLLAMA_MODELS,
    join(HOME, ".ollama"),
    HOME,
  ].filter(Boolean) as string[];

  for (const p of paths) {
    try {
      const stats = await statfs(p);
      return (stats.bfree * stats.bsize) / (1024 ** 3);
    } catch {
      // Path may not exist — try next
    }
  }
  return 999; // Unknown — don't block suggestions
}

// ── OpenRouter model check ──

type OpenRouterModel = {
  id: string;
  name: string;
  description?: string;
  context_length?: number;
  pricing: { prompt: string; completion: string };
  created?: number;
  expiration_date?: string;
};

function blendedCostPer1M(pricing: { prompt: string; completion: string }): number {
  // OpenRouter pricing is USD per token. Convert to per-1M, blend 50/50 input/output.
  const input = parseFloat(pricing.prompt) * 1_000_000;
  const output = parseFloat(pricing.completion) * 1_000_000;
  if (isNaN(input) || isNaN(output)) return Infinity;
  return (input + output) / 2;
}

function isTierCompatible(model: OpenRouterModel, tier: Tier): boolean {
  const id = model.id.toLowerCase();
  const name = (model.name ?? "").toLowerCase();
  const text = `${id} ${name}`;

  // Free / deprecated models aren't useful suggestions
  if (model.expiration_date) return false;
  const cost = blendedCostPer1M(model.pricing);
  if (cost === 0 || cost === Infinity) return false;

  const isReasoning = REASONING_KEYWORDS.some((k) => text.includes(k));
  const isComplex = COMPLEX_KEYWORDS.some((k) => text.includes(k));
  const isSmall = SMALL_KEYWORDS.some((k) => text.includes(k));

  switch (tier) {
    case "SIMPLE":
      return isSmall && !isReasoning && !isComplex;
    case "MEDIUM":
      return !isReasoning && !isComplex && !isSmall;
    case "COMPLEX":
      return isComplex && !isReasoning;
    case "REASONING":
      // Must have explicit reasoning keywords AND not be a small model.
      // Small models that happen to match a substring (e.g. "o1" in an ID)
      // are almost never suitable for reasoning-class workloads.
      return isReasoning && !isSmall;
  }
}

async function checkOpenRouterModels(minSavingsPct: number): Promise<ModelSuggestion[]> {
  const apiKey = _openrouterApiKey || _config.openrouterApiKey;
  // OpenRouter /api/v1/models is public — no key required. Key is optional for higher rate limits.

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let models: OpenRouterModel[] = [];

  try {
    const headers: Record<string, string> = {};
    if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
    const res = await fetch(OPENROUTER_MODELS_URL, {
      headers,
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      _logger.warn(`[GuardClaw Advisor] OpenRouter models API returned ${res.status}`);
      return [];
    }
    const body = await res.json() as { data?: OpenRouterModel[] };
    models = body.data ?? [];
    _logger.info(`[GuardClaw Advisor] OpenRouter: fetched ${models.length} models`);
  } catch (err) {
    clearTimeout(timer);
    _logger.warn(`[GuardClaw Advisor] OpenRouter fetch failed: ${String(err)}`);
    return [];
  }

  if (models.length === 0) {
    _logger.warn("[GuardClaw Advisor] OpenRouter returned empty model list");
    return [];
  }

  // Build lookup maps — one exact, one with version separators normalized
  // (OpenClaw config uses dashes: claude-haiku-4-5; OpenRouter uses dots: claude-haiku-4.5)
  function normalizeVersionId(id: string): string {
    // e.g. "anthropic/claude-haiku-4-5" → "anthropic/claude-haiku-4.5"
    // Only replace the very last -digit suffix with .digit
    return id.replace(/-(\d+)$/, ".$1");
  }
  const byId = new Map(models.map((m) => [m.id, m]));
  const byNormalizedId = new Map(models.map((m) => [normalizeVersionId(m.id), m]));

  // Get current tier targets from the live config token-saver options
  const privacy = getLiveConfig();
  const routers = (privacy as Record<string, unknown> & { routers?: Record<string, { options?: Record<string, unknown> }> }).routers;
  const tsOptions = (routers?.["token-saver"]?.options ?? {}) as Record<string, unknown>;
  const currentTiers = (tsOptions.tiers as Record<Tier, { provider: string; model: string }> | undefined) ?? {};

  const DEFAULT_TIERS: Record<Tier, { provider: string; model: string }> = {
    SIMPLE:    { provider: "openrouter", model: "openai/gpt-4o-mini" },
    MEDIUM:    { provider: "openrouter", model: "openai/gpt-4o" },
    COMPLEX:   { provider: "anthropic",  model: "claude-sonnet-4.6" },
    REASONING: { provider: "openai",     model: "o4-mini" },
  };

  const tiers = { ...DEFAULT_TIERS, ...currentTiers };

  const suggestions: ModelSuggestion[] = [];

  for (const [tier, target] of Object.entries(tiers) as [Tier, { provider: string; model: string }][]) {
    // Construct OpenRouter ID for the current model
    const currentId = target.model.includes("/")
      ? target.model
      : `${target.provider}/${target.model}`;

    const currentModel = byId.get(currentId) ?? byNormalizedId.get(normalizeVersionId(currentId));
    const currentCost = currentModel
      ? blendedCostPer1M(currentModel.pricing)
      : Infinity;

    if (currentCost === Infinity) continue; // Can't compare without current pricing

    // ── Three candidates per tier ─────────────────────────────────────────
    // cheapest   : lowest cost, ≥ minSavingsPct cheaper than current
    // best_value : highest (context / cost) ratio, still cheaper than current
    // best       : highest cost in tier (quality proxy), ≤ 3× current cost
    // All three must pass the tier capability filter.

    type Candidate = { model: OpenRouterModel; cost: number; savings: number };
    let cheapest: Candidate | null = null;
    let bestValue: (Candidate & { valueScore: number }) | null = null;
    let bestModel: Candidate | null = null;

    for (const model of models) {
      if (model.id === currentId) continue;
      if (!isTierCompatible(model, tier)) continue;

      const cost = blendedCostPer1M(model.pricing);
      const savings = ((currentCost - cost) / currentCost) * 100;

      // Cheapest — must beat the savings threshold
      if (savings >= minSavingsPct) {
        if (!cheapest || cost < cheapest.cost) cheapest = { model, cost, savings };
      }

      // Best value — cheaper than current, ranked by context per dollar
      if (cost < currentCost) {
        const ctx = Math.min(model.context_length ?? 4096, 200_000);
        const valueScore = ctx / cost;
        if (!bestValue || valueScore > bestValue.valueScore) {
          bestValue = { model, cost, savings, valueScore };
        }
      }

      // Best — highest quality proxy (price), cap at 3× current to stay sane
      if (cost <= currentCost * 3) {
        if (!bestModel || cost > bestModel.cost) bestModel = { model, cost, savings };
      }
    }

    const now = new Date().toISOString();
    const seen = new Set<string>();

    // 1. Cheapest
    if (cheapest) {
      const id = makeSuggestionId("openrouter_cheaper", `${tier}:${cheapest.model.id}`);
      if (!hasSuggestion(id)) {
        seen.add(cheapest.model.id);
        suggestions.push({
          id,
          type: "openrouter_cheaper",
          status: "pending",
          createdAt: now,
          title: `Cheapest ${tier} option`,
          description: `${cheapest.model.name ?? cheapest.model.id} costs ${cheapest.savings.toFixed(0)}% less than ${currentId} and passes the ${tier} capability filter.`,
          currentValue: currentId,
          suggestedValue: cheapest.model.id,
          savingsPercent: Math.round(cheapest.savings),
          details: {
            tier,
            category: "cheapest",
            currentCostPer1M: currentCost.toFixed(4),
            candidateCostPer1M: cheapest.cost.toFixed(4),
            contextLength: cheapest.model.context_length,
          },
        });
      }
    }

    // 2. Best value — skip if same model as cheapest
    if (bestValue && !seen.has(bestValue.model.id)) {
      const id = makeSuggestionId("openrouter_best_value", `${tier}:${bestValue.model.id}`);
      if (!hasSuggestion(id)) {
        seen.add(bestValue.model.id);
        const ctxK = ((bestValue.model.context_length ?? 0) / 1000).toFixed(0);
        suggestions.push({
          id,
          type: "openrouter_best_value",
          status: "pending",
          createdAt: now,
          title: `Best value ${tier} model`,
          description: `${bestValue.model.name ?? bestValue.model.id} offers the most context per dollar for ${tier} tasks${ctxK !== "0" ? ` (${ctxK}k context)` : ""}, ${bestValue.savings.toFixed(0)}% cheaper than ${currentId}.`,
          currentValue: currentId,
          suggestedValue: bestValue.model.id,
          savingsPercent: Math.round(bestValue.savings),
          details: {
            tier,
            category: "best_value",
            currentCostPer1M: currentCost.toFixed(4),
            candidateCostPer1M: bestValue.cost.toFixed(4),
            contextLength: bestValue.model.context_length,
          },
        });
      }
    }

    // 3. Best — skip if same model as a previous pick; may cost more than current
    if (bestModel && !seen.has(bestModel.model.id)) {
      const id = makeSuggestionId("openrouter_best", `${tier}:${bestModel.model.id}`);
      if (!hasSuggestion(id)) {
        const savingsStr = bestModel.savings > 0
          ? `, ${bestModel.savings.toFixed(0)}% cheaper than ${currentId}`
          : ` (${((bestModel.cost / currentCost - 1) * 100).toFixed(0)}% more than ${currentId})`;
        suggestions.push({
          id,
          type: "openrouter_best",
          status: "pending",
          createdAt: now,
          title: `Top ${tier} model`,
          description: `${bestModel.model.name ?? bestModel.model.id} is the highest-rated available model for ${tier} tasks on OpenRouter${savingsStr}.`,
          currentValue: currentId,
          suggestedValue: bestModel.model.id,
          savingsPercent: bestModel.savings > 0 ? Math.round(bestModel.savings) : undefined,
          details: {
            tier,
            category: "best",
            currentCostPer1M: currentCost.toFixed(4),
            candidateCostPer1M: bestModel.cost.toFixed(4),
            contextLength: bestModel.model.context_length,
          },
        });
      }
    }
  }

  _logger.info(`[GuardClaw Advisor] OpenRouter: ${suggestions.length} suggestion(s) after filtering`);
  return suggestions;
}

// ── LLMFit check ──

type LLMFitEntry = {
  rank?: number;
  name?: string;
  model?: string;
  score?: number;
  tokens_per_sec?: number;
  tps?: number;
  fit?: string;
  memory_gb?: number;
  context_length?: number;
  context?: number;
  quantization?: string;
  quant?: string;
  category?: string;
};

async function checkLLMFitModels(minDiskGb: number): Promise<ModelSuggestion[]> {
  // Check if llmfit is installed
  try {
    await execFileAsync("llmfit", ["--version"], { timeout: 5_000 });
  } catch {
    // Not installed or errored — skip silently
    return [];
  }

  let raw: string;
  try {
    const { stdout } = await execFileAsync("llmfit", ["recommend", "--json", "--limit", "10"], {
      timeout: 30_000,
    });
    raw = stdout;
  } catch (err) {
    _logger.warn(`[GuardClaw Advisor] LLMFit command failed: ${String(err)}`);
    return [];
  }

  let entries: LLMFitEntry[] = [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    // LLMFit may return a flat array or { models: [...] }
    const arr = Array.isArray(parsed)
      ? parsed
      : (parsed as Record<string, unknown>)?.models;
    if (!Array.isArray(arr)) {
      _logger.warn(`[GuardClaw Advisor] LLMFit: unexpected output format`);
      return [];
    }
    _logger.info(`[GuardClaw Advisor] LLMFit: parsed ${arr.length} candidate(s)`);
    // Normalize field names: LLMFit uses fit_level/estimated_tps/memory_required_gb
    entries = (arr as Record<string, unknown>[]).map((e) => ({
      name: (e.name ?? e.model) as string | undefined,
      model: e.model as string | undefined,
      fit: ((e.fit ?? e.fit_level) as string | undefined)?.toLowerCase(),
      tokens_per_sec: (e.tokens_per_sec ?? e.estimated_tps) as number | undefined,
      memory_gb: (e.memory_gb ?? e.memory_required_gb) as number | undefined,
      context_length: (e.context_length ?? e.context) as number | undefined,
      quantization: (e.quantization ?? e.quant) as string | undefined,
      rank: e.rank as number | undefined,
      score: e.score as number | undefined,
      category: e.category as string | undefined,
    }));
  } catch {
    return [];
  }

  const currentJudge = getLiveConfig().localModel?.model ?? "openbmb/minicpm4.1";

  const freeDiskGb = await getFreeDiskGb();
  const suggestions: ModelSuggestion[] = [];

  for (const entry of entries.slice(0, 5)) {
    const modelName = entry.name ?? entry.model;
    if (!modelName) continue;
    if (modelName === currentJudge) continue;
    if (entry.fit && entry.fit !== "perfect" && entry.fit !== "good") continue;

    const tps = entry.tokens_per_sec ?? entry.tps;
    const id = makeSuggestionId("local_model", modelName);
    if (hasSuggestion(id)) continue;

    // Rough model size estimate in GB (quantized ~0.5 GB per B params; use score heuristic if no size)
    const estimatedGb = entry.memory_gb ?? (entry.score ? Math.max(2, 10 - entry.score / 15) : 5);

    if (freeDiskGb < minDiskGb) {
      _logger.warn(`[GuardClaw Advisor] Skipping local model suggestion — only ${freeDiskGb.toFixed(1)} GB free (need ${minDiskGb} GB)`);
      continue;
    }

    suggestions.push({
      id,
      type: "local_model",
      status: "pending",
      createdAt: new Date().toISOString(),
      title: `Better local model: ${modelName}`,
      description: `LLMFit rates ${modelName} as "${entry.fit ?? "suitable"}" for your hardware${tps ? ` (~${Math.round(tps)} tokens/sec)` : ""}. This could replace your current judge model (${currentJudge}).`,
      currentValue: currentJudge,
      suggestedValue: modelName,
      diskRequiredGb: estimatedGb,
      pullCommand: `ollama pull ${modelName}`,
      details: {
        fit: entry.fit,
        tokensPerSec: tps,
        contextLength: entry.context_length ?? entry.context,
        quantization: entry.quantization ?? entry.quant,
        freeDiskGb: freeDiskGb.toFixed(1),
      },
    });
  }

  return suggestions;
}

// ── DeBERTa update check ──

type HFModel = {
  id: string;
  createdAt?: string;
  lastModified?: string;
};

async function checkDebertaUpdates(): Promise<ModelSuggestion[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  let hfModels: HFModel[] = [];
  try {
    const res = await fetch(HF_PROTECTAI_URL, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) return [];
    hfModels = await res.json() as HFModel[];
    if (!Array.isArray(hfModels)) return [];
  } catch {
    clearTimeout(timer);
    return [];
  }

  // Find the highest v-number for deberta-v3-base-prompt-injection
  const basePattern = /^protectai\/deberta-v3-base-prompt-injection(?:-v(\d+))?$/;
  let latestVersion = CURRENT_DEBERTA_VERSION;
  let latestId = CURRENT_DEBERTA_MODEL;

  for (const model of hfModels) {
    const m = model.id.match(basePattern);
    if (!m) continue;
    const ver = m[1] ? parseInt(m[1], 10) : 1;
    if (ver > latestVersion) {
      latestVersion = ver;
      latestId = model.id;
    }
  }

  if (latestId === CURRENT_DEBERTA_MODEL) return [];

  const id = makeSuggestionId("deberta_update", latestId);
  if (hasSuggestion(id)) return [];

  return [{
    id,
    type: "deberta_update",
    status: "pending",
    createdAt: new Date().toISOString(),
    title: `Newer injection detection model: v${latestVersion}`,
    description: `${latestId} is available on HuggingFace. Accepting updates the injection config — the new model is downloaded automatically on next startup.`,
    currentValue: CURRENT_DEBERTA_MODEL,
    suggestedValue: latestId,
    details: { currentVersion: CURRENT_DEBERTA_VERSION, latestVersion },
  }];
}

// ── Benchmarking ──

async function benchmarkModel(
  endpoint: string,
  model: string,
  providerType: EdgeProviderType,
  runs: number,
): Promise<BenchmarkResult> {
  let successes = 0;
  let totalMs = 0;
  let errors = 0;

  for (const { prompt } of BENCHMARK_PROMPTS.slice(0, runs)) {
    const start = Date.now();
    try {
      const result = await callChatCompletion(
        endpoint,
        model,
        [
          { role: "system", content: DEFAULT_JUDGE_PROMPT },
          { role: "user", content: prompt },
        ],
        { temperature: 0, maxTokens: 128, providerType },
      );
      totalMs += Date.now() - start;
      const cleaned = result.text.replace(/<think>[\s\S]*?<\/think>/g, "").trim();
      const match = cleaned.match(/\{"tier"\s*:\s*"([A-Z]+)"\}/);
      if (match && ["SIMPLE", "MEDIUM", "COMPLEX", "REASONING"].includes(match[1])) {
        successes++;
      }
    } catch {
      totalMs += Date.now() - start;
      errors++;
    }
  }

  // If every call failed the model is not locally available — throw so the
  // caller's catch block keeps the suggestion rather than dismissing it.
  if (errors === runs) {
    throw new Error(`All ${runs} benchmark calls failed — model likely unavailable`);
  }

  return {
    jsonSuccessRate: successes / BENCHMARK_PROMPTS.slice(0, runs).length,
    avgLatencyMs: Math.round(totalMs / BENCHMARK_PROMPTS.slice(0, runs).length),
    runs,
  };
}

// ── Main orchestrator ──

export async function runAdvisorChecks(): Promise<void> {
  if (_running) return;
  if (!_config.enabled) return;

  _running = true;
  _logger.info("[GuardClaw Advisor] Starting model checks…");

  try {
    const minSavings = _config.minSavingsPercent ?? 20;
    const minDisk = _config.minDiskSpaceGb ?? 10;
    const allNew: ModelSuggestion[] = [];

    // 1. OpenRouter
    if (_config.openrouter?.enabled !== false) {
      try {
        const orSuggestions = await checkOpenRouterModels(minSavings);
        allNew.push(...orSuggestions);
        if (orSuggestions.length > 0) {
          _logger.info(`[GuardClaw Advisor] OpenRouter: ${orSuggestions.length} suggestion(s)`);
        }
      } catch (err) {
        _logger.warn(`[GuardClaw Advisor] OpenRouter check failed: ${String(err)}`);
      }
    }

    // 2. LLMFit
    if (_config.llmfit?.enabled !== false) {
      try {
        const lfSuggestions = await checkLLMFitModels(minDisk);
        allNew.push(...lfSuggestions);
        if (lfSuggestions.length > 0) {
          _logger.info(`[GuardClaw Advisor] LLMFit: ${lfSuggestions.length} suggestion(s)`);
        }
      } catch (err) {
        _logger.warn(`[GuardClaw Advisor] LLMFit check failed: ${String(err)}`);
      }
    }

    // 3. DeBERTa
    if (_config.deberta?.enabled !== false) {
      try {
        const dbSuggestions = await checkDebertaUpdates();
        if (dbSuggestions.length > 0) {
          _logger.info(`[GuardClaw Advisor] DeBERTa: ${dbSuggestions.length} update suggestion(s)`);

          // Auto-update: DeBERTa is a small, critical model — apply immediately
          // rather than waiting for manual acceptance via the dashboard.
          // Can be disabled via: modelAdvisor.deberta.autoUpdate: false
          if (_config.deberta?.autoUpdate !== false) {
            for (const s of dbSuggestions) {
              // Merge into _data first so acceptSuggestion can find it
              _data.suggestions.push(s);
              const result = await acceptSuggestion(s.id);
              if (result.ok) {
                _logger.info(
                  `[GuardClaw Advisor] DeBERTa auto-updated to ${s.suggestedValue}. ` +
                  `Restart the injection service (port 8404) to load the new model.`,
                );
              } else {
                _logger.warn(`[GuardClaw Advisor] DeBERTa auto-update failed: ${result.message}`);
              }
            }
            // Already merged above — don't push to allNew again
          } else {
            allNew.push(...dbSuggestions);
          }
        }
      } catch (err) {
        _logger.warn(`[GuardClaw Advisor] DeBERTa check failed: ${String(err)}`);
      }
    }

    // 4. Optional benchmark of local model candidates
    const benchmarkEnabled = _config.benchmark?.enabled !== false;
    const benchmarkRuns = Math.min(_config.benchmark?.runs ?? 3, BENCHMARK_PROMPTS.length);

    if (benchmarkEnabled) {
      const privacy = getLiveConfig();
      const localEndpoint = privacy.localModel?.endpoint ?? "http://localhost:11434";
      const localModel = privacy.localModel?.model ?? "openbmb/minicpm4.1";
      const providerType = (privacy.localModel?.type ?? "openai-compatible") as EdgeProviderType;

      // Benchmark current judge model as baseline
      let currentBenchmark: BenchmarkResult | undefined;
      try {
        currentBenchmark = await benchmarkModel(localEndpoint, localModel, providerType, benchmarkRuns);
        _logger.info(`[GuardClaw Advisor] Current judge benchmark: ${(currentBenchmark.jsonSuccessRate * 100).toFixed(0)}% JSON success, ${currentBenchmark.avgLatencyMs}ms avg`);
      } catch (err) {
        _logger.warn(`[GuardClaw Advisor] Benchmark of current model failed: ${String(err)}`);
      }

      // Benchmark local model candidates
      for (const s of allNew.filter((s) => s.type === "local_model")) {
        const candidateModel = s.suggestedValue ?? "";
        if (!candidateModel) continue;

        try {
          const candidateBenchmark = await benchmarkModel(localEndpoint, candidateModel, providerType, benchmarkRuns);
          s.benchmarkCandidate = candidateBenchmark;
          if (currentBenchmark) s.benchmarkCurrent = currentBenchmark;

          _logger.info(
            `[GuardClaw Advisor] Candidate ${candidateModel} benchmark: ${(candidateBenchmark.jsonSuccessRate * 100).toFixed(0)}% JSON success, ${candidateBenchmark.avgLatencyMs}ms avg`,
          );

          // Drop suggestion if candidate is worse on both metrics
          if (
            currentBenchmark &&
            candidateBenchmark.jsonSuccessRate < currentBenchmark.jsonSuccessRate * 0.95 &&
            candidateBenchmark.avgLatencyMs > currentBenchmark.avgLatencyMs * 1.05
          ) {
            s.status = "dismissed";
            _logger.info(`[GuardClaw Advisor] Dismissed ${candidateModel} — benchmark below current model`);
          }
        } catch {
          // Candidate model not locally available — benchmark not possible,
          // keep the suggestion (user may pull the model later)
        }
      }
    }

    // Merge new suggestions into _data (skip dismissed ones from benchmark)
    for (const s of allNew) {
      if (s.status !== "dismissed") {
        _data.suggestions.push(s);
      }
    }

    _data.lastCheckedAt = new Date().toISOString();
    await saveAdvisorData();

    const pending = _data.suggestions.filter((s) => s.status === "pending").length;
    _logger.info(`[GuardClaw Advisor] Check complete — ${pending} pending suggestion(s)`);
  } finally {
    _running = false;
  }
}

// ── Accept / dismiss ──

export async function acceptSuggestion(id: string): Promise<{ ok: boolean; message: string }> {
  const suggestion = _data.suggestions.find((s) => s.id === id);
  if (!suggestion) return { ok: false, message: "Suggestion not found" };
  if (suggestion.status !== "pending") return { ok: false, message: `Already ${suggestion.status}` };

  try {
    if (suggestion.type === "openrouter_cheaper" || suggestion.type === "openrouter_best_value" || suggestion.type === "openrouter_best") {
      const details = suggestion.details as Record<string, unknown> | undefined;
      const tier = details?.tier as string | undefined;
      const newModel = suggestion.suggestedValue;
      if (!tier || !newModel) return { ok: false, message: "Missing tier or model in suggestion" };

      // Patch live config: update the token-saver tier
      const cfg = getLiveConfig() as Record<string, unknown>;
      const routers = ((cfg as Record<string, unknown>).routers ?? {}) as Record<string, { options?: Record<string, unknown> }>;
      if (!routers["token-saver"]) routers["token-saver"] = {};
      if (!routers["token-saver"].options) routers["token-saver"].options = {};
      const tiers = (routers["token-saver"].options.tiers ?? {}) as Record<string, { provider: string; model: string }>;
      tiers[tier] = { provider: "openrouter", model: newModel };
      routers["token-saver"].options.tiers = tiers;
      updateLiveConfig({ routers } as Parameters<typeof updateLiveConfig>[0]);

      // Persist to guardclaw.json
      const configPath = join(HOME, ".openclaw", "guardclaw.json");
      let fileCfg: Record<string, unknown> = {};
      try { fileCfg = JSON.parse(await readFile(configPath, "utf-8")) as Record<string, unknown>; } catch { /* first time */ }
      if (!fileCfg.privacy) fileCfg.privacy = {};
      const priv = fileCfg.privacy as Record<string, unknown>;
      if (!priv.routers) priv.routers = {};
      const fileRouters = priv.routers as Record<string, { options?: Record<string, unknown> }>;
      if (!fileRouters["token-saver"]) fileRouters["token-saver"] = {};
      if (!fileRouters["token-saver"].options) fileRouters["token-saver"].options = {};
      const fileTiers = (fileRouters["token-saver"].options.tiers ?? {}) as Record<string, { provider: string; model: string }>;
      fileTiers[tier] = { provider: "openrouter", model: newModel };
      fileRouters["token-saver"].options.tiers = fileTiers;
      await writeFile(configPath, JSON.stringify(fileCfg, null, 2), { encoding: "utf-8", mode: 0o600 });

      suggestion.status = "accepted";
      await saveAdvisorData();
      return { ok: true, message: `Token-saver ${tier} tier updated to ${newModel}. Config saved.` };
    }

    if (suggestion.type === "local_model") {
      // Update localModel.model in live config + disk
      const newModel = suggestion.suggestedValue;
      if (!newModel) return { ok: false, message: "Missing model name" };

      updateLiveConfig({ localModel: { ...getLiveConfig().localModel, model: newModel } });

      const configPath = join(HOME, ".openclaw", "guardclaw.json");
      let fileCfg: Record<string, unknown> = {};
      try { fileCfg = JSON.parse(await readFile(configPath, "utf-8")) as Record<string, unknown>; } catch { /* first time */ }
      if (!fileCfg.privacy) fileCfg.privacy = {};
      const priv = fileCfg.privacy as Record<string, unknown>;
      if (!priv.localModel) priv.localModel = {};
      (priv.localModel as Record<string, unknown>).model = newModel;
      await writeFile(configPath, JSON.stringify(fileCfg, null, 2), { encoding: "utf-8", mode: 0o600 });

      suggestion.status = "accepted";
      await saveAdvisorData();
      return {
        ok: true,
        message: `Local model updated to ${newModel}. ${suggestion.pullCommand ? `Pull it with: ${suggestion.pullCommand}` : "Pull the model before use."}`,
      };
    }

    if (suggestion.type === "deberta_update") {
      const newModel = suggestion.suggestedValue;
      if (!newModel) return { ok: false, message: "Missing model ID" };

      // Update injection config in guardclaw.json
      // (The deberta module reads the model ID from config on startup)
      const configPath = join(HOME, ".openclaw", "guardclaw.json");
      let fileCfg: Record<string, unknown> = {};
      try { fileCfg = JSON.parse(await readFile(configPath, "utf-8")) as Record<string, unknown>; } catch { /* first time */ }
      if (!fileCfg.injection) fileCfg.injection = {};
      (fileCfg.injection as Record<string, unknown>).deberta_model = newModel;
      await writeFile(configPath, JSON.stringify(fileCfg, null, 2), { encoding: "utf-8", mode: 0o600 });

      suggestion.status = "accepted";
      await saveAdvisorData();

      // Signal the running classifier service to hot-swap in-place.
      // Fire-and-forget with a long timeout (model download takes time).
      // If the service is down, the new model takes effect on next startup.
      triggerDebertaReload(newModel).then((r) => {
        if (r.ok) {
          _logger?.info(`[GuardClaw Advisor] DeBERTa hot-swap complete: ${r.message}`);
        } else {
          _logger?.info(`[GuardClaw Advisor] DeBERTa service unreachable (${r.message}) — new model active on next startup`);
        }
      }).catch(() => {});

      return { ok: true, message: `DeBERTa model updated to ${newModel}. Hot-reloading injection service…` };
    }

    return { ok: false, message: `Unknown suggestion type: ${suggestion.type}` };
  } catch (err) {
    return { ok: false, message: String(err) };
  }
}

export function dismissSuggestion(id: string): void {
  const s = _data.suggestions.find((s) => s.id === id);
  if (s) {
    s.status = "dismissed";
    saveAdvisorData().catch(() => {});
  }
}

export function getSuggestions(statusFilter?: SuggestionStatus): ModelSuggestion[] {
  return _data.suggestions.filter((s) => !statusFilter || s.status === statusFilter);
}

export function getLastCheckedAt(): string | null {
  return _data.lastCheckedAt;
}

// ── Initialisation & schedule ──

export async function initModelAdvisor(
  config: ModelAdvisorConfig,
  openrouterApiKey: string,
  logger: typeof _logger,
): Promise<void> {
  if (!config.enabled) return;

  _config = config;
  _openrouterApiKey = openrouterApiKey;
  _logger = logger;

  await loadAdvisorData();

  const intervalWeeks = config.checkIntervalWeeks ?? 2;
  const intervalMs = intervalWeeks * MS_PER_WEEK;

  // Run immediately if overdue
  const lastChecked = _data.lastCheckedAt ? new Date(_data.lastCheckedAt).getTime() : 0;
  if (Date.now() - lastChecked > intervalMs) {
    // Small delay so plugin startup completes first
    setTimeout(() => runAdvisorChecks().catch((err) => {
      _logger.warn(`[GuardClaw Advisor] Startup check failed: ${String(err)}`);
    }), 10_000);
  }

  // Schedule recurring checks
  if (_scheduleTimer) clearInterval(_scheduleTimer);
  _scheduleTimer = setInterval(() => {
    runAdvisorChecks().catch((err) => {
      _logger.warn(`[GuardClaw Advisor] Scheduled check failed: ${String(err)}`);
    });
  }, intervalMs);

  // Don't keep the process alive just for the advisor
  if (_scheduleTimer && typeof _scheduleTimer === "object" && "unref" in _scheduleTimer) {
    (_scheduleTimer as NodeJS.Timeout).unref();
  }

  logger.info(`[GuardClaw Advisor] Initialized (interval: ${intervalWeeks}w, ${getSuggestions("pending").length} pending suggestion(s))`);
}
