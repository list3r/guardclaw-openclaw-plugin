/**
 * GuardClaw Hooks — openclaw adaptation
 *
 * Registers all plugin hooks for sensitivity detection at various checkpoints.
 * Uses the RouterPipeline to dispatch to multiple composable routers
 * (built-in "privacy" + any user-defined custom routers).
 *
 * Architecture:
 *   before_model_resolve  → pipeline.run("onUserMessage") → RouterDecision
 *   before_prompt_build   → reads stashed decision → inject prompt/markers
 *   before_tool_call      → pipeline + memory_get path redirect (dual-track)
 *   after_tool_call       → pipeline + memory dual-write sync
 *   tool_result_persist   → PII redaction + memory_search result filtering
 *   before_message_write  → sanitize transcript based on stashed decision
 *   after_compaction      → full memory sync (FULL → clean)
 *   before_reset          → full memory sync before session clear
 *   + session_end, message_sending, before_agent_start, message_received
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import * as fs from "node:fs";
import * as path from "node:path";
import { join } from "node:path";
import type { PrivacyConfig } from "./types.js";
import {
  buildMainSessionPlaceholder,
  getGuardAgentConfig,
  isGuardSessionKey,
  isVerifiedGuardSession,
  registerGuardSessionParent,
  deregisterGuardSession,
  isLocalProvider,
} from "./guard-agent.js";
import { desensitizeWithLocalModel } from "./local-model.js";
import { syncDetectByLocalModel } from "./sync-detect.js";
import { synthesizeContent, synthesizeToolResult } from "./synthesis.js";
import { getDefaultMemoryManager, GUARD_SECTION_BEGIN, GUARD_SECTION_END } from "./memory-isolation.js";
import { loadPrompt } from "./prompt-loader.js";
import { DualSessionManager, getDefaultSessionManager, type SessionMessage } from "./session-manager.js";
import {
  markSessionAsPrivate,
  trackSessionLevel,
  recordDetection,
  isSessionMarkedPrivate,
  stashDetection,
  getPendingDetection,
  consumeDetection,
  setActiveLocalRouting,
  clearActiveLocalRouting,
  clearSessionState,
  isActiveLocalRouting,
  resetTurnLevel,
  setLastSenderId,
  getLastSenderId,
  clearLastSenderId,
  appendToRollingBuffer,
} from "./session-state.js";
import { detectByRules } from "./rules.js";
import { isProtectedMemoryPath, redactSensitiveInfo, redactForCleanTranscript, extractPathsFromParams, resolveDefaultBaseUrl, matchesPathPattern } from "./utils.js";
import {
  GUARDCLAW_S2_OPEN,
  GUARDCLAW_S2_CLOSE,
  stashOriginalProvider,
} from "./privacy-proxy.js";
import { getGlobalPipeline } from "./router-pipeline.js";
import { getGlobalCollector } from "./token-stats.js";
import { getLiveConfig, getLiveInjectionConfig, updateLiveInjectionConfig, recordInjectionAttempt, pendingBans, withConfigWriteLock } from "./live-config.js";
import { detectInjection, SECURITY_CHANNEL, formatBlockAlert } from "./injection/index.js";
import { runHeuristics } from "./injection/heuristics.js";
import { sanitiseContent } from "./injection/sanitiser.js";
import { finalizeLoop } from "./loop-detection-level.js";
import { recordFinalReply } from "./usage-intel.js";
import {
  markKeychainFetchPending,
  consumeKeychainFetchPending,
  trackSecret,
  containsTrackedSecret,
  redactTrackedSecrets,
  clearSessionSecrets,
  isNetworkTool,
  parseKeychainCommand,
} from "./secret-manager.js";
import { fireWebhooks } from "./webhook.js";
import { scanResponse } from "./response-scanner.js";
import { checkBudget, recordCost, calculateCost } from "./budget-guard.js";
import { logToolEvent, clearBehavioralSession } from "./behavioral-log.js";
import { attest } from "./behavioral-attestation.js";
import { handleUseSecret } from "./secret-ops.js";
import {
  registerTaint,
  redactTainted,
  hasTaints,
  markPendingTaint,
  consumePendingTaint,
  clearTaintSession,
  extractTaintValues,
  isSecretsMountPath,
} from "./taint-store.js";

function getPipelineConfig(): Record<string, unknown> {
  return { privacy: getLiveConfig() };
}

/** Emit a debug-level log only when guardclaw.json → privacy.debugLogging is true. */
function gcDebug(logger: { info: (msg: string) => void }, msg: string): void {
  if (getLiveConfig().debugLogging) logger.info(msg);
}

/**
 * Should this session read from the full (unredacted) memory track?
 *
 * Only sessions whose data stays entirely local may access MEMORY-FULL.md:
 *   - S3 active local routing (Guard Agent turn)
 *   - Guard sub-sessions (always local)
 *   - S2 with s2Policy === "local"
 *
 * S2-proxy sessions send data to cloud after desensitisation, so they MUST
 * read from the clean (already-redacted) MEMORY.md to avoid leaking PII
 * that regex-based tool_result_persist redaction might miss.
 */
function shouldUseFullMemoryTrack(sessionKey: string): boolean {
  if (isActiveLocalRouting(sessionKey)) return true;
  if (isVerifiedGuardSession(sessionKey)) return true;
  if (isSessionMarkedPrivate(sessionKey)) {
    const policy = getLiveConfig().s2Policy ?? "proxy";
    return policy === "local";
  }
  return false;
}

const DEFAULT_GUARD_AGENT_SYSTEM_PROMPT = `You are a privacy-aware local assistant running in a secure, air-gapped session. All data you handle stays on this machine.

RULES:
1. Analyze the data directly. Do NOT write code. Do NOT generate programming examples or tutorials.
2. NEVER echo raw sensitive values (exact salary, SSN, bank account, password, API key, token). Use generic references like "your base salary", "the SSN on file", "the stored credential", etc.
3. You MAY discuss percentages, ratios, whether deductions are correct, anomalies, and recommendations.
4. Reply ONCE, then stop. No [message_id:] tags. No multi-turn simulation.
5. **Language rule: Reply in the SAME language the user writes in.** If the user writes in Chinese, reply entirely in Chinese. If the user writes in English, reply entirely in English.
6. Be concise and professional.
7. You MUST NOT make any outbound network requests (web_fetch, http_get, curl, etc.). All operations must be local.

KEYCHAIN ACCESS (macOS only):
- To retrieve a stored secret from macOS Passwords.app / Keychain, run:
    bash -c "security find-generic-password -s 'ServiceName' -a 'AccountName' -w"
- GuardClaw automatically tracks the retrieved value and ensures it is never sent outside this machine.
- Use the secret directly in subsequent local tool calls (e.g. as an env var for a subprocess).
- NEVER include the raw secret value in your text replies. Reference it as "the stored credential" instead.

语言规则：必须使用与用户相同的语言回复。如果用户用中文提问，你必须用中文回答。`;

/**
 * Build the guard agent system prompt.
 *
 * Security rules are ALWAYS taken from DEFAULT_GUARD_AGENT_SYSTEM_PROMPT — they
 * are hardcoded and cannot be overridden from disk (#3).  Only the task section
 * (loaded from prompts/guard-agent-task.md) is user-customizable, and it is
 * appended AFTER the rules so it cannot shadow or replace them.
 *
 * This prevents an attacker who can write to the prompts directory from
 * silently disabling the "no network" or "no raw secret echo" rules.
 */
function getGuardAgentSystemPrompt(): string {
  const taskSection = loadPrompt("guard-agent-task", "");
  if (!taskSection) return DEFAULT_GUARD_AGENT_SYSTEM_PROMPT;
  return `${DEFAULT_GUARD_AGENT_SYSTEM_PROMPT}\n\n## Additional Task Instructions\n${taskSection}`;
}

/**
 * Check if a tool is exempt from privacy pipeline detection and PII redaction.
 * Reads from the live config `toolAllowlist` (default: empty = no exemptions).
 */
function isToolAllowlisted(toolName: string): boolean {
  const allowlist = getLiveConfig().toolAllowlist;
  if (!allowlist || allowlist.length === 0) return false;
  return allowlist.includes(toolName);
}

// Workspace dir cache — set from first hook that has PluginHookAgentContext
let _cachedWorkspaceDir: string | undefined;

// ── S3 synthesis pre-cache ───────────────────────────────────────────────────
// after_tool_call (async) synthesizes S3 tool results and stashes them here.
// tool_result_persist (sync) reads the stash and applies the synthetic content.
// Queue per session handles back-to-back tool calls correctly.
const _synthesisPendingQueue = new Map<string, Array<{ toolName: string; synthetic: string }>>();

function _popSynthesisPending(sessionKey: string, toolName: string): string | undefined {
  const queue = _synthesisPendingQueue.get(sessionKey);
  if (!queue || queue.length === 0) return undefined;
  const idx = queue.findIndex((e) => e.toolName === toolName);
  if (idx === -1) return undefined;
  const [entry] = queue.splice(idx, 1);
  if (queue.length === 0) _synthesisPendingQueue.delete(sessionKey);
  return entry.synthetic;
}

// GCF-003: Tool result injection detection is now performed synchronously
// inside tool_result_persist using runHeuristics() — no async pre-cache stash.
// after_tool_call 3c still runs the full DeBERTa pipeline for audit/alerting
// but no longer controls whether the tool result is blocked.

const _OPENCLAW_DIR = join(process.env.HOME ?? "/tmp", ".openclaw");
const GUARDCLAW_STATS_PATH = join(_OPENCLAW_DIR, "guardclaw-stats.json");
const GUARDCLAW_INJECTIONS_PATH = join(_OPENCLAW_DIR, "guardclaw-injections.json");
const GUARDCLAW_PENDING_CONFIG_PATH = join(_OPENCLAW_DIR, "workspace", "dashboard", "guardclaw-pending-config.json");
const GUARDCLAW_JSON_PATH = join(_OPENCLAW_DIR, "guardclaw.json");

// injectionAttemptCounts is imported from live-config.ts (shared with privacy-proxy.ts)

// GCF-026: Per-session Set of pending memory write promises.
// tool_result_persist is synchronous and fires memory writes as fire-and-forget.
// session_end and before_reset await all pending writes before proceeding.
const _pendingMemoryWrites = new Map<string, Set<Promise<void>>>();

function trackMemoryWrite(sessionKey: string, p: Promise<void>): void {
  let set = _pendingMemoryWrites.get(sessionKey);
  if (!set) { set = new Set(); _pendingMemoryWrites.set(sessionKey, set); }
  set.add(p);
  p.finally(() => { set?.delete(p); }).catch(() => {});
}

async function awaitPendingMemoryWrites(sessionKey: string, logger: { warn: (s: string) => void }): Promise<void> {
  const set = _pendingMemoryWrites.get(sessionKey);
  if (!set || set.size === 0) return;
  logger.warn(`[GuardClaw] Awaiting ${set.size} pending memory write(s) before session lifecycle event (session=${sessionKey})`);
  await Promise.allSettled([...set]);
  _pendingMemoryWrites.delete(sessionKey);
}


interface InjectionEntry {
  ts: string;
  session: string;
  senderId?: string;
  action: "block" | "sanitise";
  score: number;
  patterns: string[];
  source: string;
  preview: string;
}

async function appendInjectionLog(entry: InjectionEntry): Promise<void> {
  let entries: InjectionEntry[] = [];
  try {
    const raw = await fs.promises.readFile(GUARDCLAW_INJECTIONS_PATH, "utf8");
    try {
      const parsed = JSON.parse(raw) as InjectionEntry[];
      entries = Array.isArray(parsed) ? parsed : [];
    } catch {
      // File exists but is corrupted — start fresh rather than losing the new entry;
      // the corrupt file will be overwritten below.
    }
  } catch {
    // File doesn't exist yet — normal on first run.
  }
  entries.push(entry);
  if (entries.length > 200) entries = entries.slice(entries.length - 200);
  try {
    await fs.promises.writeFile(GUARDCLAW_INJECTIONS_PATH, JSON.stringify(entries, null, 2), { mode: 0o600 });
  } catch (err) {
    // Log write failures so operators know the audit trail has a gap.
    console.warn(`[GuardClaw S0] Failed to write injection log: ${String(err)}`);
  }
}

async function writeStatsAtomic(stats: Record<string, unknown>): Promise<void> {
  const tmp = GUARDCLAW_STATS_PATH + ".tmp";
  await fs.promises.writeFile(tmp, JSON.stringify(stats, null, 2), { mode: 0o600 });
  await fs.promises.rename(tmp, GUARDCLAW_STATS_PATH); // atomic on POSIX
}

async function updateS0Stats(action: "block" | "sanitise"): Promise<void> {
  try {
    let stats: Record<string, unknown> = { s1Count: 0, s2Count: 0, s3Count: 0, totalMessages: 0, s3Policy: "local-only", lastUpdated: null };
    try {
      const raw = await fs.promises.readFile(GUARDCLAW_STATS_PATH, "utf8");
      Object.assign(stats, JSON.parse(raw));
    } catch { /* first run */ }
    if (!stats.s0 || typeof stats.s0 !== "object") stats.s0 = { blocked: 0, sanitised: 0, total: 0 };
    const s0 = stats.s0 as Record<string, number>;
    if (action === "block") s0.blocked = (s0.blocked ?? 0) + 1;
    else s0.sanitised = (s0.sanitised ?? 0) + 1;
    s0.total = (s0.total ?? 0) + 1;
    await writeStatsAtomic(stats);
  } catch { /* best-effort */ }
}

async function updateSynthesisStats(
  source: "user_message" | "tool_result",
  latencyMs: number,
  ok: boolean,
): Promise<void> {
  try {
    let stats: Record<string, unknown> = {};
    try {
      const raw = await fs.promises.readFile(GUARDCLAW_STATS_PATH, "utf8");
      Object.assign(stats, JSON.parse(raw));
    } catch { /* first run */ }

    if (!stats.synthesis || typeof stats.synthesis !== "object") stats.synthesis = {};
    const syn = stats.synthesis as Record<string, unknown>;

    if (!syn[source] || typeof syn[source] !== "object") {
      syn[source] = { count: 0, failCount: 0, totalMs: 0, minMs: null, maxMs: null, lastMs: null, recentSamples: [] };
    }
    const bucket = syn[source] as Record<string, unknown>;

    if (!ok) {
      bucket.failCount = ((bucket.failCount as number) ?? 0) + 1;
    } else {
      bucket.count = ((bucket.count as number) ?? 0) + 1;
      bucket.totalMs = ((bucket.totalMs as number) ?? 0) + latencyMs;
      bucket.minMs = bucket.minMs == null ? latencyMs : Math.min(bucket.minMs as number, latencyMs);
      bucket.maxMs = bucket.maxMs == null ? latencyMs : Math.max(bucket.maxMs as number, latencyMs);
      bucket.lastMs = latencyMs;
      const samples = (bucket.recentSamples as number[]) ?? [];
      samples.push(latencyMs);
      if (samples.length > 50) samples.shift(); // keep last 50 for p95
      bucket.recentSamples = samples;
    }

    await writeStatsAtomic(stats);
  } catch { /* best-effort */ }
}

async function updateGuardclawStats(level: string): Promise<void> {
  try {
    let stats: Record<string, unknown> = { s1Count: 0, s2Count: 0, s3Count: 0, totalMessages: 0, s3Policy: "local-only", lastUpdated: null };
    try {
      const raw = await fs.promises.readFile(GUARDCLAW_STATS_PATH, "utf8");
      Object.assign(stats, JSON.parse(raw));
    } catch { /* first run or missing file */ }
    if (level === "S1") stats.s1Count = (stats.s1Count as number) + 1;
    else if (level === "S2") stats.s2Count = (stats.s2Count as number) + 1;
    else if (level === "S3") stats.s3Count = (stats.s3Count as number) + 1;
    stats.totalMessages = (stats.totalMessages as number) + 1;
    stats.lastUpdated = new Date().toISOString();
    await writeStatsAtomic(stats);
  } catch { /* stats are best-effort */ }
}

export function registerHooks(api: OpenClawPluginApi): void {
  const privacyCfgInit = getLiveConfig();
  const sessionBaseDir = privacyCfgInit.session?.baseDir;

  const memoryManager = getDefaultMemoryManager();
  memoryManager.initializeDirectories().catch((err) => {
    api.logger.error(`[GuardClaw] Failed to initialize memory directories: ${String(err)}`);
  });

  getDefaultSessionManager(sessionBaseDir);

  // ── Pending config watcher: apply s3Policy changes from dashboard ─────────
  setInterval(async () => {
    try {
      await fs.promises.access(GUARDCLAW_PENDING_CONFIG_PATH);
      const pendingRaw = await fs.promises.readFile(GUARDCLAW_PENDING_CONFIG_PATH, "utf8");
      const pending = JSON.parse(pendingRaw) as Record<string, unknown>;
      const s3Policy = pending.s3Policy as string;
      if (!s3Policy) return;
      const cfgRaw = await fs.promises.readFile(GUARDCLAW_JSON_PATH, "utf8");
      const cfg = JSON.parse(cfgRaw) as Record<string, unknown>;
      if (!cfg.privacy) cfg.privacy = {};
      (cfg.privacy as Record<string, unknown>).s3Policy = s3Policy;
      await fs.promises.writeFile(GUARDCLAW_JSON_PATH, JSON.stringify(cfg, null, 2));
      await fs.promises.unlink(GUARDCLAW_PENDING_CONFIG_PATH);
      api.logger.info(`[GuardClaw] s3Policy updated to: ${s3Policy}`);
      // Reflect new policy in stats file
      try {
        const statsRaw = await fs.promises.readFile(GUARDCLAW_STATS_PATH, "utf8");
        const stats = JSON.parse(statsRaw) as Record<string, unknown>;
        stats.s3Policy = s3Policy;
        await fs.promises.writeFile(GUARDCLAW_STATS_PATH, JSON.stringify(stats, null, 2));
      } catch { /* non-critical */ }
    } catch { /* file not present — normal */ }
  }, 5000);

  // =========================================================================
  // Hook 1: before_model_resolve — Run pipeline + model routing
  // =========================================================================
  api.on("before_model_resolve", async (event, ctx) => {
    try {
      const { prompt } = event;
      const sessionKey = ctx.sessionKey ?? "";
      if (!sessionKey || !prompt) return;

      clearActiveLocalRouting(sessionKey);
      resetTurnLevel(sessionKey);
      consumeDetection(sessionKey);

      const privacyConfig = getLiveConfig();
      if (!privacyConfig.enabled) return;

      // ── Budget guard — check before pipeline runs ──────────────────────────
      const budgetCfg = privacyConfig.budget;
      if (budgetCfg?.enabled) {
        const budgetStatus = checkBudget(budgetCfg);
        if (budgetStatus.exceeded) {
          const msg = `Budget cap exceeded — daily: $${budgetStatus.dailyCost.toFixed(4)}${budgetCfg.dailyCap ? `/$${budgetCfg.dailyCap}` : ""}, monthly: $${budgetStatus.monthlyCost.toFixed(4)}${budgetCfg.monthlyCap ? `/$${budgetCfg.monthlyCap}` : ""}`;
          api.logger.warn(`[GuardClaw] ${msg}`);
          const hooks = privacyConfig.webhooks ?? [];
          fireWebhooks("budget_exceeded", { sessionKey, reason: msg }, hooks);
          if (budgetStatus.action === "block") {
            throw new Error(`[GuardClaw] Request blocked: ${msg}`);
          }
          if (budgetStatus.action === "pause_cloud") {
            api.logger.info("[GuardClaw] Budget exceeded — routing to local model");
            const guardCfg = getGuardAgentConfig(privacyConfig);
            const localProvider = guardCfg?.provider ?? privacyConfig.localModel?.provider ?? "ollama";
            const localModel = guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "qwen/qwen3-30b-a3b-2507";
            return { providerOverride: localProvider, modelOverride: localModel };
          }
        } else if (budgetStatus.warning) {
          const msg = `Budget warning — daily: $${budgetStatus.dailyCost.toFixed(4)}${budgetCfg.dailyCap ? `/$${budgetCfg.dailyCap}` : ""}, monthly: $${budgetStatus.monthlyCost.toFixed(4)}${budgetCfg.monthlyCap ? `/$${budgetCfg.monthlyCap}` : ""}`;
          api.logger.warn(`[GuardClaw] ${msg}`);
          const hooks = privacyConfig.webhooks ?? [];
          fireWebhooks("budget_warning", { sessionKey, reason: msg }, hooks);
        }
      }

      if (isGuardSessionKey(sessionKey)) {
        // S0: Run injection detection for guard sessions (no sender-ban check —
        // guard inputs don't have a meaningful sender ID, but tool-result injections
        // targeting the guard agent still need to be caught).
        const guardInjCfg = getLiveInjectionConfig();
        if (guardInjCfg.enabled !== false) {
          const guardMsgStr = String(prompt);
          const guardContent = extractUserContent(guardMsgStr) ?? guardMsgStr;
          try {
            const guardInjResult = await detectInjection(guardContent, "user_message", guardInjCfg);
            if (guardInjResult.action === "block") {
              api.logger.warn(
                `[GuardClaw S0] BLOCKED guard session injection: session=${sessionKey} score=${guardInjResult.score} patterns=${guardInjResult.matches.join(",")}`,
              );
              recordDetection(sessionKey, "S0", "onUserMessage", guardInjResult.blocked_reason ?? "Prompt injection in guard session");
              throw new Error(`[GuardClaw S0] Guard session message blocked: ${guardInjResult.blocked_reason ?? "Prompt injection detected"}`);
            }
          } catch (err) {
            const msg = String(err);
            if (msg.includes("[GuardClaw S0] Guard session message blocked")) throw err;
            api.logger.warn(`[GuardClaw S0] Guard session detection error (non-fatal): ${msg}`);
          }
        }

        const guardCfg = getGuardAgentConfig(privacyConfig);
        if (guardCfg) {
          return { providerOverride: guardCfg.provider, modelOverride: guardCfg.modelName };
        }
        return;
      }

      if (ctx.workspaceDir) _cachedWorkspaceDir = ctx.workspaceDir;

      const msgStr = String(prompt);
      if (shouldSkipMessage(msgStr)) return;

      // ── GCF-034: s2Channels fast path ─────────────────────────────────────
      // Channels pre-classified as S2 skip the full pipeline (saves ~600ms LLM
      // classification + ~1-2s LLM desensitization). Uses regex-only redaction
      // + proxy defense-in-depth. S0 injection detection still runs below.
      const s2ChannelSet = new Set((privacyConfig as Record<string, unknown>).s2Channels as string[] ?? []);
      const channelId = ctx.channelId ?? "";
      if (channelId && s2ChannelSet.has(channelId)) {
        gcDebug(api.logger, `[GuardClaw] s2Channels fast path: channel=${channelId}`);

        // S0 injection detection still runs on pre-classified channels
        const injCfgFast = getLiveInjectionConfig();
        if (injCfgFast.enabled !== false) {
          const rawExtracted = extractUserContent(msgStr);
          const userContent = rawExtracted ? stripThreadContextPrefix(rawExtracted) : stripThreadContextPrefix(msgStr) || null;
          if (userContent) {
            try {
              const injResult = await detectInjection(userContent, "user_message", injCfgFast);
              if (injResult.action === "block") {
                throw new Error(`[GuardClaw S0] Message blocked: ${injResult.blocked_reason ?? "Prompt injection detected"}`);
              }
            } catch (err) {
              const msg = String(err);
              if (msg.includes("[GuardClaw S0] Message blocked")) throw err;
            }
          }
        }

        // Regex-only desensitization (preRedactCredentials + redactSensitiveInfo)
        const { preRedactCredentials } = await import("./local-model.js");
        const desensitized = redactSensitiveInfo(preRedactCredentials(msgStr), privacyConfig.redaction);

        recordDetection(sessionKey, "S2", "onUserMessage", "s2Channels pre-classified");
        updateGuardclawStats("S2").catch(() => {});
        markSessionAsPrivate(sessionKey, "S2");
        stashDetection(sessionKey, {
          level: "S2",
          reason: "s2Channels pre-classified",
          desensitized,
          originalPrompt: msgStr,
          timestamp: Date.now(),
        });

        // Route through privacy proxy
        const defaults = api.config.agents?.defaults as Record<string, unknown> | undefined;
        const primaryModel = (defaults?.model as Record<string, unknown> | undefined)?.primary as string ?? "";
        const defaultProvider = (defaults?.provider as string) || primaryModel.split("/")[0] || "openai";
        const providerConfig = api.config.models?.providers?.[defaultProvider];
        if (providerConfig) {
          const pc = providerConfig as Record<string, unknown>;
          const providerApi = (pc.api as string) ?? undefined;
          stashOriginalProvider(sessionKey, {
            baseUrl: (pc.baseUrl as string) ?? resolveDefaultBaseUrl(defaultProvider, providerApi),
            apiKey: (pc.apiKey as string) ?? "",
            provider: defaultProvider,
            api: providerApi,
          });
        }
        return { providerOverride: "guardclaw-privacy" };
      }

      // ── S0: Prompt injection detection (runs before S1/S2/S3 pipeline) ──
      const injectionCfg = getLiveInjectionConfig();
      if (injectionCfg.enabled !== false) {
        // Extract senderId: prefer ctx.senderId, then the value stashed by
        // message_received (before the Discord envelope was stripped from prompt),
        // then fall back to regex on the raw prompt string (rarely succeeds now).
        let senderId = (ctx as Record<string, unknown>).senderId as string | undefined;
        if (!senderId && ctx.channelId) {
          senderId = getLastSenderId(ctx.channelId);
          clearLastSenderId(ctx.channelId);
        }
        if (!senderId) {
          // Tertiary fallback: envelope may still be present in some edge cases
          const senderMatch = msgStr.match(/"sender_id"\s*:\s*"(\d+)"/);
          if (senderMatch) senderId = senderMatch[1];
        }
        // Build a Set once for O(1) ban/exempt lookups (#10)
        const bannedSet = new Set(injectionCfg.banned_senders ?? []);
        // Check if sender is banned (auto-block immediately, no detection needed)
        const isBannedSender = senderId && bannedSet.has(senderId);
        if (isBannedSender) {
          api.logger.warn(`[GuardClaw S0] BANNED sender blocked: senderId=${senderId} session=${sessionKey}`);
          recordDetection(sessionKey, 'S0', 'onUserMessage', `Banned sender: ${senderId}`);
          fireWebhooks("ban_triggered", { sessionKey, reason: `Banned sender: ${senderId}`, details: { senderId: senderId ?? "" } }, privacyConfig.webhooks ?? []);
          throw new Error(`[GuardClaw S0] Message blocked: Sender ${senderId} is banned`);
        }

        const isExemptSender = senderId && new Set(injectionCfg.exempt_senders ?? []).has(senderId);

        // Audit log for every exempt-sender bypass so the skip is visible (#13)
        if (isExemptSender) {
          gcDebug(api.logger, `[GuardClaw S0] Exempt sender bypass — skipping injection check: senderId=${senderId} session=${sessionKey}`);
        }

        if (!isExemptSender) {
          // Extract actual user content from OpenClaw envelope (Discord/iMessage/Telegram).
          // Also strip any thread-context prefix so DeBERTa doesn't see OpenClaw's own
          // role labels (🤖 claude, [Thread starter...]) as injection signals.
          const rawExtracted = extractUserContent(msgStr);
          const userContent = rawExtracted ? stripThreadContextPrefix(rawExtracted) : stripThreadContextPrefix(msgStr) || null;
          if (!userContent) {
            // No user content found — skip injection detection for pure metadata
            api.logger.debug?.(`[GuardClaw S0] Skipping injection check — no user content extracted`);
          } else {
          try {
            const injResult = await detectInjection(userContent, 'user_message', injectionCfg);
            if (injResult.action === 'block') {
              api.logger.warn(
                `[GuardClaw S0] BLOCKED session=${sessionKey} score=${injResult.score} patterns=${injResult.matches.join(',')}`,
              );
              await appendInjectionLog({
                ts: new Date().toISOString(),
                session: sessionKey,
                senderId: senderId,
                action: 'block',
                score: injResult.score,
                patterns: injResult.matches,
                source: 'user_message',
                // GCF-011: Redact before logging — false-positive blocks may contain real secrets.
                preview: redactSensitiveInfo(msgStr.slice(0, 80), getLiveConfig().redaction),
              });
              void updateS0Stats('block');
              // Auto-ban logic: track injection attempts per senderId
              if (senderId) {
                const attempts = recordInjectionAttempt(senderId);
                const alreadyBanned = bannedSet.has(senderId);
                if (attempts >= 2 && !alreadyBanned && !pendingBans.has(senderId)) {
                  pendingBans.add(senderId);
                  api.logger.warn(`[GuardClaw S0] AUTO-BANNING senderId=${senderId} after ${attempts} injection attempts`);
                  const newBanned = [...(injectionCfg.banned_senders ?? []), senderId];
                  updateLiveInjectionConfig({ banned_senders: newBanned });
                  // GCF-024: Persist under mutex to prevent concurrent auto-ban RMW races.
                  withConfigWriteLock(async () => {
                    const raw = await fs.promises.readFile(GUARDCLAW_JSON_PATH, 'utf8');
                    const cfg = JSON.parse(raw) as Record<string, unknown>;
                    if (!cfg.privacy) cfg.privacy = {};
                    const privacy = cfg.privacy as Record<string, unknown>;
                    if (!privacy.injection) privacy.injection = {};
                    (privacy.injection as Record<string, unknown>).banned_senders = newBanned;
                    await fs.promises.writeFile(GUARDCLAW_JSON_PATH, JSON.stringify(cfg, null, 2), { encoding: 'utf-8', mode: 0o600 });
                  })
                    .catch((err) => { api.logger.warn(`[GuardClaw S0] Failed to persist ban for ${senderId}: ${String(err)}`); })
                    .finally(() => { pendingBans.delete(senderId ?? ''); });
                }
              }
              // Record in session state so dashboard /api/detections picks it up
              recordDetection(sessionKey, 'S0', 'onUserMessage', injResult.blocked_reason ?? 'Prompt injection detected');
              // Send alert to Discord security channel (best-effort, fire-and-forget)
              const alertChannel = injectionCfg.alert_channel ?? SECURITY_CHANNEL;
              const alertMsg = formatBlockAlert(injResult, 'user_message', msgStr);
              void (api as unknown as Record<string, Record<string, (a: string, b: string) => Promise<void>>>)
                .discord?.sendMessage?.(alertChannel, alertMsg)?.catch?.(() => {});
              // Block the message by throwing — prevents model invocation
              throw new Error(
                `[GuardClaw S0] Message blocked: ${injResult.blocked_reason ?? 'Prompt injection detected'}`,
              );
            } else if (injResult.action === 'sanitise' && injResult.sanitised) {
              api.logger.warn(
                `[GuardClaw S0] SANITISED session=${sessionKey} score=${injResult.score} patterns=${injResult.matches.join(',')}`,
              );
              await appendInjectionLog({
                ts: new Date().toISOString(),
                session: sessionKey,
                action: 'sanitise',
                score: injResult.score,
                patterns: injResult.matches,
                source: 'user_message',
                // GCF-011: Redact before logging.
                preview: redactSensitiveInfo(msgStr.slice(0, 80), getLiveConfig().redaction),
              });
              void updateS0Stats('sanitise');
              // Record in session state so dashboard /api/detections picks it up
              recordDetection(sessionKey, 'S0', 'onUserMessage', `Injection sanitised (score ${Math.round(injResult.score)})`);
              // Re-scan sanitised content: a sophisticated payload may partially survive
              // sanitisation but still trigger S2/S3 sensitivity rules. Escalate to
              // block if any privacy rule fires on the cleaned text. (#11)
              const sanitiseRecheck = detectByRules(
                { checkpoint: "onUserMessage", message: injResult.sanitised, sessionKey },
                privacyConfig,
              );
              if (sanitiseRecheck.level !== "S1") {
                api.logger.warn(
                  `[GuardClaw S0] Sanitised content still triggers ${sanitiseRecheck.level} — escalating to block. reason=${sanitiseRecheck.reason}`,
                );
                recordDetection(sessionKey, "S0", "onUserMessage", `Post-sanitise escalation: ${sanitiseRecheck.reason}`);
                throw new Error(`[GuardClaw S0] Message blocked after sanitise re-check: ${sanitiseRecheck.reason}`);
              }
              // Replace the prompt with sanitised content for the rest of the pipeline
              (event as unknown as Record<string, unknown>).prompt = injResult.sanitised;
            }
          } catch (err) {
            // Re-throw block errors; swallow other S0 errors (non-fatal)
            const msg = String(err);
            api.logger.warn(`[GuardClaw S0] CATCH: ${msg}`);
            if (msg.includes('[GuardClaw S0] Message blocked')) throw err;
            api.logger.warn(`[GuardClaw S0] Detection error (non-fatal): ${msg}`);
          }
          } // close else (userContent found)
        } // close !isExemptSender
      } // close injection enabled

      // ── S3 fast path: rule-based pre-check ──────────────────────────
      // Rules are synchronous and deterministic. When they detect S3 we
      // can route to the local model immediately — no need to run the
      // full pipeline (LLM detector, token-saver, custom routers, etc.)
      // which would waste compute and needlessly expose sensitive content.
      const rulePreCheck = detectByRules(
        { checkpoint: "onUserMessage", message: msgStr, sessionKey },
        privacyConfig,
      );

      if (rulePreCheck.level === "S3") {
        recordDetection(sessionKey, "S3", "onUserMessage", rulePreCheck.reason);
        updateGuardclawStats("S3").catch(() => {});
        trackSessionLevel(sessionKey, "S3");

        // ── s3Policy: "redact-and-forward" (lightweight mode) ──────────────
        // Off by default. Enable in guardclaw.json:
        //   "privacy": { "s3Policy": "redact-and-forward" }
        //
        // Instead of routing to a local guard agent, aggressively redacts
        // all S3 content (credentials, paths, secrets) then forwards to cloud.
        // WARNING: Redaction quality determines security — test thoroughly before use.
        // Designed for 16 GB standalone deployments without a guard agent server.
        const s3Policy = (privacyConfig as Record<string, unknown>).s3Policy as string ?? "local-only";
        if (s3Policy === "redact-and-forward") {
          api.logger.warn(`[GuardClaw] S3 redact-and-forward mode — aggressively redacting before cloud`);
          stashDetection(sessionKey, {
            level: "S2", // treat as S2 so desensitization pipeline runs
            reason: `s3-redact-forward: ${rulePreCheck.reason}`,
            originalPrompt: msgStr,
            timestamp: Date.now(),
          });
          // Fall through to S2 handling — will desensitize and forward
          // The S3 patterns are a superset of S2, so redaction will be maximal
          return; // let before_prompt_build handle S2 desensitization
        } else if (s3Policy === "synthesize") {
          // ── s3Policy: "synthesize" (transparent mode) ────────────────────
          // Processes S3 content locally and injects a natural-language synthesis
          // back into the conversation. Neither the cloud model nor the user sees
          // that interception happened — the exchange appears seamless.
          //
          // Enable in guardclaw.json:
          //   "privacy": { "s3Policy": "synthesize" }
          //
          // Falls back to "local-only" if synthesis fails or local model is unreachable.
          gcDebug(api.logger, "[GuardClaw] S3 synthesize mode — processing locally before cloud");

          // Build task context from recent conversation (helps synthesis be relevant)
          const taskContext = (params.messages ?? [])
            .slice(-4)
            .map((m: { role: string; content: string }) => `${m.role}: ${String(m.content).slice(0, 200)}`)
            .join("\n");

          const _synthT0 = Date.now();
          const synthResult = await synthesizeContent(
            userMessage,
            taskContext,
            privacyConfig,
            sessionKey,
          );
          const _synthLatency = Date.now() - _synthT0;
          updateSynthesisStats("user_message", _synthLatency, synthResult.ok).catch(() => {});

          if (synthResult.ok) {
            gcDebug(api.logger, `[GuardClaw] S3 synthesis complete — forwarding to cloud (${_synthLatency}ms)`);
            // Save full content to local track, synthetic to clean track
            if (sessionMgr) {
              sessionMgr.appendToFullHistory(sessionKey, { role: "user", content: userMessage });
              sessionMgr.appendToCleanHistory(sessionKey, { role: "user", content: synthResult.synthetic });
            }
            // Replace the message going to the cloud model with the synthesis
            params.messages = (params.messages ?? []).map(
              (m: { role: string; content: string }, i: number, arr: unknown[]) =>
                i === arr.length - 1 && m.role === "user"
                  ? { ...m, content: synthResult.synthetic }
                  : m,
            );
            // Continue to cloud — do NOT fall through to guard agent
          } else {
            api.logger.warn(`[GuardClaw] S3 synthesis failed (${synthResult.reason}) — falling back to local-only`);
            // Fall through to guard agent routing below
            stashDetection(sessionKey, { level: "S3", reason: `synthesis-fallback: ${synthResult.reason}` });
            // redirect to guard agent (same as local-only path)
          }
        }

        setActiveLocalRouting(sessionKey);
        registerGuardSessionParent(sessionKey); // #12: register before guard session spawns
        stashDetection(sessionKey, {
          level: "S3",
          reason: rulePreCheck.reason,
          originalPrompt: msgStr,
          timestamp: Date.now(),
        });

        const guardCfg = getGuardAgentConfig(privacyConfig);
        const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
        const provider = guardCfg?.provider ?? defaultProvider;
        const model = guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "qwen/qwen3-30b-a3b-2507";
        gcDebug(api.logger, `[GuardClaw] S3 (rule fast-path) — routing to ${provider}/${model}`);
        return { providerOverride: provider, modelOverride: model };
      }

      // ── Normal path: run the full router pipeline ──────────────────
      const pipeline = getGlobalPipeline();
      if (!pipeline) {
        api.logger.warn("[GuardClaw] Router pipeline not initialized");
        return;
      }

      const decision = await pipeline.run(
        "onUserMessage",
        {
          checkpoint: "onUserMessage",
          message: prompt,
          sessionKey,
          agentId: ctx.agentId,
        },
        getPipelineConfig(),
      );

      recordDetection(sessionKey, decision.level, "onUserMessage", decision.reason);
      updateGuardclawStats(decision.level).catch(() => {});
      gcDebug(api.logger, `[GuardClaw] ROUTE: session=${sessionKey} level=${decision.level} action=${decision.action} target=${JSON.stringify(decision.target)} reason=${decision.reason}`);

      // Dispatch webhooks for S2/S3 detections
      if (decision.level === "S3" || decision.level === "S2") {
        const webhooks = privacyConfig.webhooks ?? [];
        if (webhooks.length > 0) {
          const event = decision.level === "S3" ? "s3_detected" : "s2_detected";
          fireWebhooks(event, { sessionKey, level: decision.level, reason: decision.reason }, webhooks);
        }
      }

      if (decision.level === "S1" && decision.action === "passthrough") {
        return;
      }

      // ── GCF-034: Auto-learn — promote channel to s2Channels on first S2 detection ──
      // When the LLM classifier detects S2 for a channel not yet in s2Channels,
      // auto-add it so subsequent messages skip the LLM entirely.
      if (decision.level === "S2" && channelId && !s2ChannelSet.has(channelId)) {
        s2ChannelSet.add(channelId);
        const updatedChannels = [...s2ChannelSet];
        // Hot-update live config
        updateLiveConfig({ s2Channels: updatedChannels } as Partial<PrivacyConfig>);
        // Persist to guardclaw.json (fire-and-forget, under write lock)
        withConfigWriteLock(async () => {
          try {
            const raw = await fs.promises.readFile(GUARDCLAW_JSON_PATH, "utf8");
            const cfg = JSON.parse(raw) as Record<string, unknown>;
            if (!cfg.privacy) cfg.privacy = {};
            (cfg.privacy as Record<string, unknown>).s2Channels = updatedChannels;
            await fs.promises.writeFile(GUARDCLAW_JSON_PATH, JSON.stringify(cfg, null, 2), { mode: 0o600 });
          } catch { /* best-effort */ }
        }).catch(() => {});
        api.logger.info(`[GuardClaw] Auto-learned S2 channel: ${channelId} (${updatedChannels.length} total)`);
      }

      // S3 from LLM detector (rules didn't catch it above): route to local
      if (decision.level === "S3") {
        trackSessionLevel(sessionKey, "S3");
        setActiveLocalRouting(sessionKey);
        registerGuardSessionParent(sessionKey); // #12: register before guard session spawns
        stashDetection(sessionKey, {
          level: "S3",
          reason: decision.reason,
          originalPrompt: msgStr,
          timestamp: Date.now(),
        });
        if (decision.target) {
          gcDebug(api.logger, `[GuardClaw] S3 — routing to ${decision.target.provider}/${decision.target.model} [${decision.routerId}]`);
          return {
            providerOverride: decision.target.provider,
            ...(decision.target.model ? { modelOverride: decision.target.model } : {}),
          };
        }
        const guardCfg = getGuardAgentConfig(privacyConfig);
        const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
        gcDebug(api.logger, `[GuardClaw] S3 — routing to ${guardCfg?.provider ?? defaultProvider}/${guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "qwen/qwen3-30b-a3b-2507"} [${decision.routerId}]`);
        return {
          providerOverride: guardCfg?.provider ?? defaultProvider,
          modelOverride: guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "qwen/qwen3-30b-a3b-2507",
        };
      }

      // Desensitize for S2 (needed for both proxy markers and local prompt).
      // If desensitization fails (local model down), escalate to S3 so the
      // message stays entirely local — never send raw PII to cloud.
      let desensitized: string | undefined;
      if (decision.level === "S2") {
        const result = await desensitizeWithLocalModel(msgStr, privacyConfig, sessionKey);
        if (result.failed) {
          api.logger.warn("[GuardClaw] S2 desensitization failed — escalating to S3 (local-only) to prevent PII leak");
          trackSessionLevel(sessionKey, "S3");
          setActiveLocalRouting(sessionKey);
          registerGuardSessionParent(sessionKey); // #12: register before guard session spawns
          stashDetection(sessionKey, {
            level: "S3",
            reason: `${decision.reason}; desensitization failed — escalated to S3`,
            originalPrompt: msgStr,
            timestamp: Date.now(),
          });
          const guardCfg = getGuardAgentConfig(privacyConfig);
          const fallbackProvider = privacyConfig.localModel?.provider ?? "ollama";
          return {
            providerOverride: guardCfg?.provider ?? fallbackProvider,
            modelOverride: guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "qwen/qwen3-30b-a3b-2507",
          };
        }
        desensitized = result.desensitized;
      }

      // Stash decision for before_prompt_build / before_message_write
      stashDetection(sessionKey, {
        level: decision.level,
        reason: decision.reason,
        desensitized,
        originalPrompt: msgStr,
        timestamp: Date.now(),
      });

      // S2-local: route to edge model
      if (decision.level === "S2" && decision.action === "redirect" && decision.target?.provider !== "guardclaw-privacy") {
        markSessionAsPrivate(sessionKey, decision.level);
        if (decision.target) {
          gcDebug(api.logger, `[GuardClaw] S2 — routing to ${decision.target.provider}/${decision.target.model} [${decision.routerId}]`);
          return {
            providerOverride: decision.target.provider,
            ...(decision.target.model ? { modelOverride: decision.target.model } : {}),
          };
        }
      }

      // S2-proxy path
      if (decision.level === "S2" && decision.target?.provider === "guardclaw-privacy") {
        markSessionAsPrivate(sessionKey, "S2");
        const defaults = api.config.agents?.defaults as Record<string, unknown> | undefined;
        const primaryModel = (defaults?.model as Record<string, unknown> | undefined)?.primary as string ?? "";
        const defaultProvider = (defaults?.provider as string) || primaryModel.split("/")[0] || "openai";
        const providerConfig = api.config.models?.providers?.[defaultProvider];
        if (providerConfig) {
          const pc = providerConfig as Record<string, unknown>;
          const providerApi = (pc.api as string) ?? undefined;
          const stashTarget = {
            baseUrl: (pc.baseUrl as string) ?? resolveDefaultBaseUrl(defaultProvider, providerApi),
            apiKey: (pc.apiKey as string) ?? "",
            provider: defaultProvider,
            api: providerApi,
          };
          stashOriginalProvider(sessionKey, stashTarget);
        }
        const modelInfo = decision.target.model ? ` (model=${decision.target.model})` : "";
        gcDebug(api.logger, `[GuardClaw] S2 — routing through privacy proxy${modelInfo} [${decision.routerId}]`);
        return {
          providerOverride: "guardclaw-privacy",
          ...(decision.target.model ? { modelOverride: decision.target.model } : {}),
        };
      }

      // Non-privacy routers may return redirect with a custom target
      if (decision.action === "redirect" && decision.target) {
        gcDebug(api.logger, `[GuardClaw] ${decision.level} — custom route to ${decision.target.provider}/${decision.target.model} [${decision.routerId}]`);
        return {
          providerOverride: decision.target.provider,
          ...(decision.target.model ? { modelOverride: decision.target.model } : {}),
        };
      }

      // Block action at model resolve level → route to edge model as safeguard
      if (decision.action === "block") {
        if (decision.level === "S3") {
          trackSessionLevel(sessionKey, "S3");
          setActiveLocalRouting(sessionKey);
        } else {
          markSessionAsPrivate(sessionKey, decision.level);
        }
        const guardCfg = getGuardAgentConfig(privacyConfig);
        const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
        api.logger.warn(`[GuardClaw] ${decision.level} BLOCK — redirecting to edge model [${decision.routerId}]`);
        return {
          providerOverride: guardCfg?.provider ?? defaultProvider,
          modelOverride: guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "qwen/qwen3-30b-a3b-2507",
        };
      }

      // Transform action: the router rewrote the prompt content.
      // For S2/S3 we must still route safely — use the transformed content
      // as the desensitized payload and route through the appropriate path.
      if (decision.action === "transform") {
        if (decision.level === "S3") {
          trackSessionLevel(sessionKey, "S3");
          setActiveLocalRouting(sessionKey);
          registerGuardSessionParent(sessionKey); // #12: register before guard session spawns
          stashDetection(sessionKey, {
            level: "S3",
            reason: decision.reason,
            originalPrompt: msgStr,
            timestamp: Date.now(),
          });
          const guardCfg = getGuardAgentConfig(privacyConfig);
          const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
          gcDebug(api.logger, `[GuardClaw] S3 TRANSFORM — routing to edge model [${decision.routerId}]`);
          return {
            providerOverride: guardCfg?.provider ?? defaultProvider,
            modelOverride: guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "qwen/qwen3-30b-a3b-2507",
          };
        }

        if (decision.level === "S2") {
          const transformedText = decision.transformedContent ?? desensitized ?? msgStr;
          stashDetection(sessionKey, {
            level: "S2",
            reason: decision.reason,
            desensitized: transformedText,
            originalPrompt: msgStr,
            timestamp: Date.now(),
          });
          markSessionAsPrivate(sessionKey, "S2");

          const s2Policy = privacyConfig.s2Policy ?? "proxy";
          if (s2Policy === "local") {
            const guardCfg = getGuardAgentConfig(privacyConfig);
            const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
            gcDebug(api.logger, `[GuardClaw] S2 TRANSFORM — routing to local ${guardCfg?.provider ?? defaultProvider} [${decision.routerId}]`);
            return {
              providerOverride: guardCfg?.provider ?? defaultProvider,
              modelOverride: guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "qwen/qwen3-30b-a3b-2507",
            };
          }

          // S2-proxy: route through privacy proxy to strip any residual PII
          const defaults = api.config.agents?.defaults as Record<string, unknown> | undefined;
          const primaryModel = (defaults?.model as Record<string, unknown> | undefined)?.primary as string ?? "";
          const defaultProvider = (defaults?.provider as string) || primaryModel.split("/")[0] || "openai";
          const providerConfig = api.config.models?.providers?.[defaultProvider];
          if (providerConfig) {
            const pc = providerConfig as Record<string, unknown>;
            const providerApi = (pc.api as string) ?? undefined;
            stashOriginalProvider(sessionKey, {
              baseUrl: (pc.baseUrl as string) ?? resolveDefaultBaseUrl(defaultProvider, providerApi),
              apiKey: (pc.apiKey as string) ?? "",
              provider: defaultProvider,
              api: providerApi,
            });
          }
          gcDebug(api.logger, `[GuardClaw] S2 TRANSFORM — routing through privacy proxy [${decision.routerId}]`);
          return { providerOverride: "guardclaw-privacy" };
        }

        // S1 + transform: no sensitive data, let original provider handle it
        return;
      }

      // Default: no override — let the original provider handle the request
      // so provider-specific sanitization (Google turn ordering, tool schema
      // cleaning, transcript policy) in openclaw core still triggers correctly.
      return;
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_model_resolve hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 2: before_prompt_build — Inject guard prompt / S2 markers /
  //         dual-track history for local models
  // =========================================================================
  api.on("before_prompt_build", async (_event, ctx) => {
    try {
      const sessionKey = ctx.sessionKey ?? "";
      if (!sessionKey) return;

      const pending = getPendingDetection(sessionKey);
      if (!pending || pending.level === "S1") return;

      const privacyConfig = getLiveConfig();
      const sessionCfg = privacyConfig.session ?? {};
      const shouldInject = sessionCfg.injectDualHistory !== false
        && sessionCfg.isolateGuardHistory !== false;
      const historyLimit = sessionCfg.historyLimit ?? 20;

      // S3: data processed entirely locally. Inject full-track history
      // so the local model sees previous S3 interactions that were replaced
      // by "🔒 [Private content]" placeholders in the main transcript.
      if (pending.level === "S3") {
        if (shouldInject) {
          const context = await loadDualTrackContext(sessionKey, ctx.agentId, historyLimit);
          if (context) {
            gcDebug(api.logger, `[GuardClaw] Injected dual-track history context for S3 turn`);
            return { prependContext: context };
          }
        }
        return;
      }

      const s2Policy = privacyConfig.s2Policy ?? "proxy";

      // S2-local: data stays on-device — inject full-track history for richer context.
      if (pending.level === "S2" && s2Policy === "local") {
        if (shouldInject) {
          const context = await loadDualTrackContext(sessionKey, ctx.agentId, historyLimit);
          if (context) {
            gcDebug(api.logger, `[GuardClaw] Injected dual-track history context for S2-local turn`);
            return { prependContext: context };
          }
        }
        return;
      }

      // S2-proxy: inject desensitized content wrapped in markers for privacy-proxy to strip.
      //
      // SAFETY CONTRACT: OpenClaw's before_prompt_build `prependContext` prepends
      // text directly to the user prompt string (see plugin.md §Prompt build order).
      // The resulting message content becomes:
      //   "<guardclaw-s2>\n{desensitized}\n</guardclaw-s2>\n\n{original PII}"
      // The proxy's stripPiiMarkers() replaces the ENTIRE content with only the text
      // between markers, effectively discarding the original PII that follows.
      // If OpenClaw ever changes prependContext semantics (e.g. to a separate message),
      // the proxy's fallback regex redaction provides defense-in-depth.
      if (pending.level === "S2" && pending.desensitized) {
        return {
          prependContext: `${GUARDCLAW_S2_OPEN}\n${pending.desensitized}\n${GUARDCLAW_S2_CLOSE}`,
        };
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_prompt_build hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 3: before_tool_call — Run pipeline at onToolCallProposed
  // =========================================================================
  api.on("before_tool_call", async (event, ctx) => {
    try {
      const { toolName, params } = event;
      const sessionKey = ctx.sessionKey ?? "";
      if (!toolName) return;

      const typedParams = params as Record<string, unknown>;
      const privacyConfig = getLiveConfig();
      const baseDir = privacyConfig.session?.baseDir ?? "~/.openclaw";

      // ── Behavioral attestation logging ────────────────────────────────────
      // Log every tool call when enabled. Guard sessions are excluded —
      // they run in a trusted local context with different threat model.
      const baConfig = (privacyConfig as Record<string, unknown> & {
        behavioralAttestation?: { enabled?: boolean; logOnly?: boolean; windowSize?: number; blockThreshold?: number }
      }).behavioralAttestation;
      if (baConfig?.enabled && !isVerifiedGuardSession(sessionKey)) {
        const currentLevel = getPendingDetection(sessionKey)?.level ?? null;
        logToolEvent(sessionKey, toolName, typedParams, currentLevel);
      }

      // ── use_secret intercept ──────────────────────────────────────────────
      // Virtual tool: never reaches the actual executor. GuardClaw resolves the
      // credential locally, runs behavioral attestation + LLM intent verification,
      // executes the operation, and returns only the result — the raw secret value
      // never enters the agent's context.
      if (toolName === "use_secret") {
        const secretResult = await handleUseSecret(
          typedParams,
          sessionKey,
          privacyConfig,
          privacyConfig.webhooks,
          api.logger,
        );
        if (!secretResult.ok) {
          // Block with a denial message the agent can act on
          return {
            block: true,
            blockReason: `[GuardClaw:secrets] Access denied — ${secretResult.reason}`,
          };
        }
        // The SDK doesn't support synthetic results from before_tool_call,
        // so we surface the operation result via blockReason. The agent sees
        // this as a guardrail message that contains the result it requested.
        return {
          block: true,
          blockReason: `[GuardClaw:secrets] Operation succeeded\n---\n${secretResult.result}`,
        };
      }

      // ── Guard session controls ─────────────────────────────────────────────
      // Guard Agent sessions run entirely locally (S3 isolation).  They have
      // elevated trust for local tools but must be prevented from exfiltrating
      // secrets via network calls or by leaking secret values in tool params.
      // Use isVerifiedGuardSession (#12) to prevent session-key forgery attacks.
      if (isVerifiedGuardSession(sessionKey)) {
        // 1. Block all outbound network tools unconditionally.
        if (isNetworkTool(toolName)) {
          api.logger.warn(
            `[GuardClaw] BLOCKED guard session network tool: ${toolName} (session=${sessionKey})`,
          );
          return {
            block: true,
            blockReason: `GuardClaw: network tools are blocked in guard sessions to prevent secret exfiltration (${toolName})`,
          };
        }

        // 2. Detect macOS Keychain fetch commands so the result can be tracked.
        //    security find-generic-password -w prints the password to stdout.
        const bashCmd = String(typedParams.command ?? typedParams.cmd ?? typedParams.script ?? "");
        if (bashCmd && parseKeychainCommand(bashCmd)) {
          markKeychainFetchPending(sessionKey);
          gcDebug(api.logger, `[GuardClaw] Guard session keychain fetch detected — result will be tracked (session=${sessionKey})`);
        }

        // 2b. Block bash commands that make outbound network connections (#1).
        //     Scans the full raw command string, which covers $(...) and backtick
        //     sub-expressions — the literal tool name is present regardless of nesting.
        if (isExecTool(toolName) && bashCmd) {
          const networkTool = isGuardNetworkCommand(bashCmd);
          if (networkTool) {
            api.logger.warn(
              `[GuardClaw] BLOCKED guard session network command via bash: ${networkTool} (session=${sessionKey})`,
            );
            return {
              block: true,
              blockReason: `GuardClaw: outbound network commands are blocked in guard sessions to prevent secret exfiltration (${networkTool})`,
            };
          }
        }

        // 3. Scan tool parameters for any already-tracked secrets.
        //    Block if a tracked secret would be sent outside the local environment.
        const paramStr = JSON.stringify(typedParams);
        if (containsTrackedSecret(sessionKey, paramStr)) {
          api.logger.warn(
            `[GuardClaw] BLOCKED guard session tool "${toolName}": params contain a tracked secret (session=${sessionKey})`,
          );
          return {
            block: true,
            blockReason: `GuardClaw: tool parameters contain a tracked Keychain secret and cannot be called in this context (${toolName})`,
          };
        }
      }

      // File-access guard for cloud models only — local models (Guard Agent
      // sessions and S3 active routing) are trusted to read full history.
      if (!isVerifiedGuardSession(sessionKey) && !isActiveLocalRouting(sessionKey)) {
        const pathValues = extractPathsFromParams(typedParams);
        for (const p of pathValues) {
          if (isProtectedMemoryPath(p, baseDir)) {
            api.logger.warn(`[GuardClaw] BLOCKED: cloud model tried to access protected path: ${p}`);
            return { block: true, blockReason: `GuardClaw: access to full history/memory is restricted for cloud models (${p})` };
          }
        }

        // ── GCF-004: S3 path pre-blocking for cloud model sessions ────────────
        // Block ALL tool calls (not just exec) when a cloud-model session
        // attempts to access S3 paths or secrets mounts. This prevents the
        // late-detection window (tool_result_persist is too late — cloud model
        // already has the data in context). Blocking here prevents exposure.
        const s3Paths = privacyConfig.rules?.tools?.S3?.paths ?? [];
        for (const p of pathValues) {
          if (isSecretsMountPath(p)) {
            api.logger.warn(
              `[GuardClaw GCF-004] BLOCKED cloud-session tool "${toolName}": secrets-mount path "${p}" — ` +
              `would expose secrets to cloud model (session=${sessionKey})`,
            );
            return {
              block: true,
              blockReason: `GuardClaw: secrets-mount paths are not accessible from cloud-model sessions — use a guard session for sensitive file access (${p})`,
            };
          }
          if (s3Paths.length > 0 && matchesPathPattern(p, s3Paths)) {
            api.logger.warn(
              `[GuardClaw GCF-004] BLOCKED cloud-session tool "${toolName}": S3 path "${p}" — ` +
              `would expose sensitive data to cloud model (session=${sessionKey})`,
            );
            return {
              block: true,
              blockReason: `GuardClaw: S3 path access is blocked for cloud-model sessions — use a guard session for sensitive file operations (${p})`,
            };
          }
        }

        // ── Taint: detect secrets-mount reads ──────────────────────────────────
        // When the agent reads from /run/secrets/ or /var/run/secrets/, flag the
        // session so tool_result_persist can register the content as tainted.
        // Note: this is now a fallback — GCF-004 blocks secrets-mount reads above.
        const _taintBtcCfg = (privacyConfig as Record<string, unknown> & {
          taintTracking?: { enabled?: boolean }
        }).taintTracking;
        if (_taintBtcCfg?.enabled !== false) {
          for (const p of pathValues) {
            if (isSecretsMountPath(p)) {
              markPendingTaint(sessionKey, `secrets-file:${p}`, "S3");
              gcDebug(api.logger, `[GuardClaw:taint] Secrets-mount read detected — result will be taint-tracked (path=${p}, session=${sessionKey})`);
              // GCF-014: No break — queue all paths, one entry per tool call.
            }
          }
        }
      }

      // Memory read routing: only fully-local sessions read from MEMORY-FULL.md.
      // S2-proxy sessions stay on the clean track to avoid leaking PII to cloud.
      if (toolName === "memory_get" && shouldUseFullMemoryTrack(sessionKey)) {
        const p = String(typedParams.path ?? "");
        if (p === "MEMORY.md" || p === "memory.md") {
          return { params: { ...typedParams, path: "MEMORY-FULL.md" } };
        }
        if (p.startsWith("memory/")) {
          return { params: { ...typedParams, path: p.replace(/^memory\//, "memory-full/") } };
        }
      }

      // Subagent / A2A guard (rule-based only — no LLM detector overhead)
      const isSpawn = toolName === "sessions_spawn";
      const isSend = toolName === "sessions_send";
      if (isSpawn || isSend) {
        const contentField = isSpawn ? String(typedParams?.task ?? "") : String(typedParams?.message ?? "");
        if (contentField.trim()) {
          const ruleResult = detectByRules(
            { checkpoint: "onToolCallProposed", message: contentField, toolName, toolParams: typedParams, sessionKey },
            privacyConfig,
          );
          recordDetection(sessionKey, ruleResult.level, "onToolCallProposed", ruleResult.reason);
          updateGuardclawStats(ruleResult.level).catch(() => {});

          if (ruleResult.level === "S3") {
            trackSessionLevel(sessionKey, "S3");
            return { block: true, blockReason: `GuardClaw: ${isSpawn ? "subagent task" : "A2A message"} blocked — S3 (${ruleResult.reason ?? "sensitive"})` };
          }
          if (ruleResult.level === "S2") {
            markSessionAsPrivate(sessionKey, "S2");
          }
        }
      }

      // ── Exec command pre-screening ──────────────────────────────────
      // Block exec commands that are likely to produce secrets in stdout.
      // This is the only reliable interception point — after_tool_call is
      // a void hook (can't modify output) and tool_result_persist only
      // modifies persisted data, not the live model context.
      if (isExecTool(toolName) && !isActiveLocalRouting(sessionKey) && !isVerifiedGuardSession(sessionKey)) {
        const command = String(typedParams.command ?? typedParams.cmd ?? typedParams.script ?? "");
        if (command) {
          const blocked = isHighRiskExecCommand(command);
          if (blocked) {
            api.logger.warn(`[GuardClaw] BLOCKED high-risk exec command: ${command.slice(0, 80)}`);
            recordDetection(sessionKey, "S3", "onToolCallProposed", `high-risk exec: ${blocked}`);
            updateGuardclawStats("S3").catch(() => {});
            trackSessionLevel(sessionKey, "S3");
            return { block: true, blockReason: `GuardClaw: exec command blocked — likely to output secrets (${blocked}). Use a local model session for this operation.` };
          }
        }
      }

      // General tool call detection.
      // S3 local routing: the model is already local — re-running detection
      // would block the very tool calls the local model needs.
      // Internal infrastructure tools are also exempt from detection.
      //
      // Detection method is config-driven: when onToolCallProposed includes
      // "localModelDetector" the full pipeline runs (LLM + rules); otherwise
      // only fast rule-based detection is used (default).
      if (!isActiveLocalRouting(sessionKey) && !isToolAllowlisted(toolName)) {
        const detectors = privacyConfig.checkpoints?.onToolCallProposed ?? ["ruleDetector"];
        const usePipeline = detectors.includes("localModelDetector");
        let level: "S1" | "S2" | "S3" = "S1";
        let reason: string | undefined;

        if (usePipeline) {
          const pipeline = getGlobalPipeline();
          if (pipeline) {
            const decision = await pipeline.run(
              "onToolCallProposed",
              { checkpoint: "onToolCallProposed", toolName, toolParams: typedParams, sessionKey },
              getPipelineConfig(),
            );
            level = decision.level;
            reason = decision.reason;
          }
        } else {
          const ruleResult = detectByRules(
            { checkpoint: "onToolCallProposed", toolName, toolParams: typedParams, sessionKey },
            privacyConfig,
          );
          level = ruleResult.level;
          reason = ruleResult.reason;
        }

        recordDetection(sessionKey, level, "onToolCallProposed", reason);
        updateGuardclawStats(level).catch(() => {});

        if (level === "S3") {
          trackSessionLevel(sessionKey, "S3");
          return { block: true, blockReason: `GuardClaw: tool "${toolName}" blocked — S3 (${reason ?? "sensitive"})` };
        }
        if (level === "S2") {
          markSessionAsPrivate(sessionKey, "S2");
        }
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_tool_call hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 3b: after_tool_call — async S3 synthesis pre-cache
  //   Runs BEFORE tool_result_persist. If s3Policy is "synthesize", detects
  //   S3 content in the tool result and synthesizes it via the local model.
  //   The result is stashed in _synthesisPendingQueue for tool_result_persist
  //   to apply synchronously, without needing to await there.
  // =========================================================================
  api.on("after_tool_call", async (event, ctx) => {
    try {
      const sessionKey = ctx.sessionKey ?? "";
      if (!sessionKey) return;

      const privacyConfig = getLiveConfig();
      if ((privacyConfig.s3Policy ?? "local-only") !== "synthesize") return;
      if (!privacyConfig.localModel?.enabled) return;
      if (isActiveLocalRouting(sessionKey)) return;
      if (isVerifiedGuardSession(sessionKey)) return;
      if (ctx.toolName && isToolAllowlisted(ctx.toolName)) return;

      // Extract result text — OpenClaw may expose it in different shapes
      const ev = event as Record<string, unknown>;
      const raw = ev.output ?? ev.result ?? ev.text ?? ev.content ?? "";
      const textContent = typeof raw === "string" ? raw : JSON.stringify(raw);
      if (!textContent || textContent.length < 10) return;

      // Only synthesize if rules detect S3 — skip cheaper S1/S2 results
      const ruleCheck = detectByRules(
        { checkpoint: "onToolCallExecuted", toolName: ctx.toolName, toolResult: textContent, sessionKey },
        privacyConfig,
      );
      if (ruleCheck.level !== "S3") return;

      gcDebug(api.logger, `[GuardClaw] S3 in tool result — synthesizing before tool_result_persist (tool=${ctx.toolName ?? "unknown"})`);

      const taskContext = `Tool "${ctx.toolName ?? "unknown"}" returned a result that needs to stay private.`;
      const _synthT0 = Date.now();
      const synthResult = await synthesizeToolResult(
        ctx.toolName ?? "unknown",
        textContent,
        taskContext,
        privacyConfig,
        sessionKey,
      );
      const _synthLatency = Date.now() - _synthT0;
      updateSynthesisStats("tool_result", _synthLatency, synthResult.ok).catch(() => {});

      if (synthResult.ok) {
        const queue = _synthesisPendingQueue.get(sessionKey) ?? [];
        queue.push({ toolName: ctx.toolName ?? "", synthetic: synthResult.synthetic });
        _synthesisPendingQueue.set(sessionKey, queue);
        gcDebug(api.logger, `[GuardClaw] Synthesis stashed for tool_result_persist — ${_synthLatency}ms (tool=${ctx.toolName ?? "unknown"})`);
      } else {
        api.logger.warn(`[GuardClaw] Tool result synthesis failed after ${_synthLatency}ms (${synthResult.reason}) — tool_result_persist will redact normally`);
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in after_tool_call synthesis: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 3c: after_tool_call — S0 injection detection on tool results
  //   Runs BEFORE tool_result_persist. Detects prompt injection attempts
  //   embedded in tool results (web pages, API responses, file content).
  //   Stashes block/sanitise decisions for tool_result_persist to apply.
  // =========================================================================
  api.on("after_tool_call", async (event, ctx) => {
    try {
      const sessionKey = ctx.sessionKey ?? "";
      if (!sessionKey) return;
      if (isActiveLocalRouting(sessionKey)) return;
      if (isVerifiedGuardSession(sessionKey)) return;
      if (ctx.toolName && isToolAllowlisted(ctx.toolName)) return;

      const injectionCfg = getLiveInjectionConfig();
      if (injectionCfg.enabled === false) return;

      const ev = event as Record<string, unknown>;
      const raw = ev.output ?? ev.result ?? ev.text ?? ev.content ?? "";
      const textContent = typeof raw === "string" ? raw : JSON.stringify(raw);
      if (!textContent || textContent.length < 20) return;

      // Map tool name to an injection source type so users can exempt
      // specific source classes via config.exempt_sources
      const toolName = ctx.toolName ?? "";
      let source: import("./injection/index.js").InjectionSource = "api_response";
      if (/web.?fetch|http.?fetch/i.test(toolName)) source = "web_fetch";
      else if (/read.?file|file.?read/i.test(toolName)) source = "file";

      // GCF-003: DeBERTa runs here for enhanced audit/alerting only.
      // tool_result_persist now blocks/sanitises synchronously via heuristics,
      // removing the async ordering dependency on this hook completing first.
      const injResult = await detectInjection(textContent, source, injectionCfg);
      if (injResult.action === "block" || injResult.action === "sanitise") {
        api.logger.warn(
          `[GuardClaw S0] DeBERTa audit: tool result injection confirmed: tool=${toolName} score=${injResult.score} ` +
          `patterns=${injResult.matches.join(",")} session=${sessionKey}`,
        );
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in after_tool_call injection check: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 4: tool_result_persist
  //         + memory_search filtering + memory dual-write sync
  // =========================================================================
  api.on("tool_result_persist", (event, ctx) => {
    try {
      const sessionKey = ctx.sessionKey ?? "";
      if (!sessionKey) return;

      const msg = event.message;
      if (!msg) return;

      // ── Memory dual-write sync ──
      // When Agent writes to memory files, sync the other track.
      if (ctx.toolName === "write" || ctx.toolName === "write_file") {
        const writePath = String(((event as Record<string, unknown>).params as Record<string, unknown> | undefined)?.path ?? "");
        if (writePath && isMemoryWritePath(writePath)) {
          const workspaceDir = _cachedWorkspaceDir ?? process.cwd();
          const privacyConfig = getLiveConfig();
          // GCF-008: Use isVerifiedGuardSession (registry-checked) not isGuardSessionKey
          // (pattern-only) to prevent session-key spoofing from gaining guard write access.
          // GCF-026: Track the write promise so session_end/before_reset can await it.
          const writePromise = syncMemoryWrite(writePath, workspaceDir, privacyConfig, api.logger, isVerifiedGuardSession(sessionKey))
            .catch((err) => { api.logger.warn(`[GuardClaw] Memory dual-write sync failed: ${String(err)}`); });
          trackMemoryWrite(sessionKey, writePromise);
        }
      }

      // ── memory_search result filtering ──
      // QMD indexes both MEMORY.md and MEMORY-FULL.md (via extraPaths).
      // Filter out the wrong track so each session type only sees its own.
      if (ctx.toolName === "memory_search") {
        const filtered = filterMemorySearchResults(msg, shouldUseFullMemoryTrack(sessionKey));
        if (filtered) return { message: filtered };
        return;
      }

      // ── S3 local routing: dual-track split ──
      // The local model sees full content (via dual-track history injection),
      // but the main transcript must be redacted so future S1 turns don't
      // leak S3 tool results to cloud models.
      if (isActiveLocalRouting(sessionKey)) {
        const textContent = extractMessageText(msg);
        if (textContent && textContent.length >= 10) {
          const sessionManager = getDefaultSessionManager();
          sessionManager.writeToFull(sessionKey, {
            role: "tool", content: textContent, timestamp: Date.now(), sessionKey,
          }).catch(() => {});
          const redacted = redactForCleanTranscript(textContent, getLiveConfig().redaction);
          if (redacted !== textContent) {
            gcDebug(api.logger, `[GuardClaw] S3 tool result PII-redacted for transcript (tool=${ctx.toolName ?? "unknown"})`);
            sessionManager.writeToClean(sessionKey, {
              role: "tool", content: redacted, timestamp: Date.now(), sessionKey,
            }).catch(() => {});
            const modified = replaceMessageText(msg, redacted);
            if (modified) return { message: modified };
          } else {
            sessionManager.writeToClean(sessionKey, {
              role: "tool", content: textContent, timestamp: Date.now(), sessionKey,
            }).catch(() => {});
          }
        }
        return;
      }

      // ── Guard session tool results ─────────────────────────────────────────
      // Guard Agent tool results never go to the clean transcript (isGuardAgentMessage
      // in session-manager filters them), but we still need to:
      //   a) Track bash results that came from Keychain fetch commands.
      //   b) Redact tracked secrets from the guard session's own persisted transcript
      //      (the full.jsonl) as an extra safety net — the guard may echo the secret.
      if (isVerifiedGuardSession(sessionKey)) {
        const resultText = extractMessageText(msg);
        if (resultText) {
          // Track result as a secret if this is a pending Keychain bash fetch.
          if (consumeKeychainFetchPending(sessionKey)) {
            const secretValue = resultText.trim();
            trackSecret(sessionKey, secretValue);
            gcDebug(api.logger, `[GuardClaw] Guard session Keychain secret tracked (session=${sessionKey})`);
            // Replace the persisted result with a redacted placeholder so the raw
            // secret value is never written to full.jsonl either.
            const redactedResult = redactTrackedSecrets(sessionKey, resultText);
            if (redactedResult !== resultText) {
              const modified = replaceMessageText(msg, redactedResult);
              if (modified) return { message: modified };
            }
          } else {
            // For non-keychain results, still redact any previously tracked secrets.
            const redactedResult = redactTrackedSecrets(sessionKey, resultText);
            if (redactedResult !== resultText) {
              const modified = replaceMessageText(msg, redactedResult);
              if (modified) return { message: modified };
            }
          }
        }
        return;
      }

      // Internal infrastructure tools (gateway, web_fetch, etc.) naturally contain
      // auth headers/tokens that must NOT be redacted or the tool breaks.
      if (ctx.toolName && isToolAllowlisted(ctx.toolName)) return;

      const textContent = extractMessageText(msg);
      if (!textContent || textContent.length < 10) return;

      // ── GCF-030: Tool-noise early exit ────────────────────────────────────
      // Short status messages from tool calls ("✓ Created", "Running grep...",
      // exit codes, whitespace-only) are overwhelmingly S1. Running them
      // through the full S2 pipeline (rules, rolling buffer, injection
      // heuristics, sync LLM, taint tracking) generates useless proxy
      // requests that amplify into TCP connection storms during multi-tool
      // turns. Skip the heavy path for clearly benign output; still write
      // to dual-track for audit if the session is already private.
      if (textContent.length < 200 && isToolNoise(textContent, ctx.toolName)) {
        if (isSessionMarkedPrivate(sessionKey)) {
          const sessionManager = getDefaultSessionManager();
          sessionManager.writeToFull(sessionKey, {
            role: "tool", content: textContent, timestamp: Date.now(), sessionKey,
          }).catch(() => {});
          sessionManager.writeToClean(sessionKey, {
            role: "tool", content: textContent, timestamp: Date.now(), sessionKey,
          }).catch(() => {});
        }
        return;
      }

      // ── GCF-002: Cross-turn rolling buffer detection ──────────────────────
      // Append content to the per-session 500-char sliding window and run
      // full pattern detection on it.  This catches secrets split across
      // two consecutive tool results (e.g. a PEM key returned in chunks).
      {
        const rollingBuf = appendToRollingBuffer(sessionKey, textContent);
        if (rollingBuf.length >= 10) {
          const rollingPrivCfg = getLiveConfig();
          const rollingCheck = detectByRules(
            { checkpoint: "onToolCallExecuted", toolName: ctx.toolName, toolResult: rollingBuf, sessionKey },
            rollingPrivCfg,
          );
          if (rollingCheck.level === "S2" || rollingCheck.level === "S3") {
            api.logger.warn(
              `[GuardClaw:rolling] Cross-turn sensitive content detected level=${rollingCheck.level} session=${sessionKey} reason=${rollingCheck.reason ?? ""}`,
            );
            markSessionAsPrivate(sessionKey, rollingCheck.level);
            recordDetection(sessionKey, rollingCheck.level, "onToolCallExecuted", `[rolling-buffer] ${rollingCheck.reason ?? ""}`);
          }
        }
      }

      // ── S0: Synchronous injection detection (GCF-003) ────────────────────
      // Run heuristics synchronously so blocking is guaranteed regardless of
      // async after_tool_call ordering. DeBERTa still runs there for enhanced
      // audit logging, but tool_result_persist is the enforcement point.
      const injectionCfgTrp = getLiveInjectionConfig();
      if (injectionCfgTrp.enabled !== false) {
        const toolNameTrp = ctx.toolName ?? "";
        let sourceTrp: import("./injection/index.js").InjectionSource = "api_response";
        if (/web.?fetch|http.?fetch/i.test(toolNameTrp)) sourceTrp = "web_fetch";
        else if (/read.?file|file.?read/i.test(toolNameTrp)) sourceTrp = "file";
        if (!injectionCfgTrp.exempt_sources?.includes(sourceTrp)) {
          const blockThresholdTrp = injectionCfgTrp.block_threshold ?? 70;
          const sanitiseThresholdTrp = injectionCfgTrp.sanitise_threshold ?? 30;
          const heuristic = runHeuristics(textContent);
          if (heuristic.score >= sanitiseThresholdTrp) {
            const injAction = heuristic.score >= blockThresholdTrp ? "block" : "sanitise";
            const injReason = `Injection detected (heuristics score ${heuristic.score}): ${heuristic.matches.join(", ")}`;
            void appendInjectionLog({
              ts: new Date().toISOString(),
              session: sessionKey,
              action: injAction,
              score: heuristic.score,
              patterns: heuristic.matches,
              source: sourceTrp,
              preview: redactSensitiveInfo(textContent.slice(0, 80), getLiveConfig().redaction),
            });
            void updateS0Stats(injAction);
            recordDetection(sessionKey, "S0", "onToolCallExecuted", injReason);
            if (injAction === "block") {
              api.logger.warn(
                `[GuardClaw S0] Tool result blocked (injection heuristics): tool=${toolNameTrp} score=${heuristic.score} session=${sessionKey}`,
              );
              const blocked = replaceMessageText(msg,
                `[GuardClaw S0: Tool result blocked — prompt injection detected. Score: ${heuristic.score}, patterns: ${heuristic.matches.join(", ")}]`);
              if (blocked) return { message: blocked };
            } else {
              gcDebug(api.logger,
                `[GuardClaw S0] Tool result sanitised (injection heuristics): tool=${toolNameTrp} score=${heuristic.score} session=${sessionKey}`,
              );
              const sanitisedText = sanitiseContent(textContent, heuristic.matchedPatterns);
              const sanitised = replaceMessageText(msg, sanitisedText);
              if (sanitised) return { message: sanitised };
            }
          }
        }
      }

      // ── Detection + PII redaction + state tracking + dual-track writing ──
      // This sync hook is the single handler for tool result privacy:
      // it is the only hook that can modify the persisted transcript.
      const privacyConfig = getLiveConfig();

      // Snapshot the turn-level privacy state BEFORE detection runs.
      // markSessionAsPrivate() updates currentTurnLevel immediately, so
      // checking isSessionMarkedPrivate() later would always be true
      // after any S2/S3 detection — causing the LLM dual-write fallback
      // (below) to incorrectly skip.
      const wasPrivateBefore = isSessionMarkedPrivate(sessionKey);

      // ── Taint tracking: extract config + consume pending registration ─────────
      const _taintCfg = (privacyConfig as Record<string, unknown> & {
        taintTracking?: { enabled?: boolean; minValueLength?: number; trackS2?: boolean }
      }).taintTracking;
      const taintEnabled = _taintCfg?.enabled !== false;
      const taintMinLen = _taintCfg?.minValueLength ?? 8;

      if (taintEnabled) {
        // Consume any pending taint from a secrets-mount read in before_tool_call.
        const pendingTaint = consumePendingTaint(sessionKey);
        if (pendingTaint) {
          const taintVals = extractTaintValues(textContent, taintMinLen);
          for (const v of taintVals) {
            registerTaint(sessionKey, v, pendingTaint.source, pendingTaint.sensitivity, taintMinLen);
          }
          if (taintVals.length > 0) {
            gcDebug(api.logger,
              `[GuardClaw:taint] Registered ${taintVals.length} tainted value(s) from ${pendingTaint.source} (session=${sessionKey})`,
            );
          }
        }
      }

      const ruleCheck = detectByRules(
        {
          checkpoint: "onToolCallExecuted",
          toolName: ctx.toolName,
          toolResult: textContent,
          sessionKey,
        },
        privacyConfig,
      );

      const detectedSensitive = ruleCheck.level === "S3" || ruleCheck.level === "S2";

      // S3 detected at tool_result_persist is TOO LATE for local routing:
      // the cloud model is already processing this turn and has seen prior
      // context. Setting activeLocalRouting here would be misleading.
      // Instead, degrade to S2 behaviour: record S3 for audit, but apply
      // S2-level treatment (PII redaction) since that is the strongest
      // mitigation still available at this stage.
      const effectiveLevel = ruleCheck.level === "S3" ? "S2" as const : ruleCheck.level;

      if (detectedSensitive) {
        trackSessionLevel(sessionKey, ruleCheck.level); // audit: record true S3
        markSessionAsPrivate(sessionKey, effectiveLevel);
        recordDetection(sessionKey, ruleCheck.level, "onToolCallExecuted", ruleCheck.reason);
        updateGuardclawStats(ruleCheck.level).catch(() => {});
        if (ruleCheck.level === "S3") {
          api.logger.warn(
            `[GuardClaw] S3 detected in tool result AFTER cloud model already active — ` +
            `degrading to S2 (PII redaction). tool=${ctx.toolName ?? "unknown"}, reason=${ruleCheck.reason ?? "rule-match"}`,
          );
        }
      }

      // ── Taint: register values from S3-detected (and optionally S2) content ──
      // Forward-taints values extracted from sensitive tool results so they are
      // redacted if they appear in any FUTURE tool result in this session.
      if (taintEnabled && (ruleCheck.level === "S3" || (ruleCheck.level === "S2" && _taintCfg?.trackS2))) {
        const taintValsFromResult = extractTaintValues(textContent, taintMinLen);
        const taintSource = `${ruleCheck.level.toLowerCase()}-tool-result:${ctx.toolName ?? "unknown"}`;
        const taintSens = ruleCheck.level === "S3" ? "S3" as const : "S2" as const;
        for (const v of taintValsFromResult) {
          registerTaint(sessionKey, v, taintSource, taintSens, taintMinLen);
        }
        if (taintValsFromResult.length > 0) {
          gcDebug(api.logger,
            `[GuardClaw:taint] Registered ${taintValsFromResult.length} tainted value(s) from ${ruleCheck.level} tool result (tool=${ctx.toolName ?? "unknown"}, session=${sessionKey})`,
          );
        }
      }

      // ── s3Policy: synthesize — apply pre-cached synthetic content ──
      // after_tool_call (async) already synthesized this result and stashed it.
      // Use the synthesis instead of blunt redaction: the cloud model gets a
      // natural-language description rather than [REDACTED] placeholders.
      if (ruleCheck.level === "S3" && (privacyConfig.s3Policy ?? "local-only") === "synthesize") {
        const synthetic = _popSynthesisPending(sessionKey, ctx.toolName ?? "");
        if (synthetic) {
          const sessionManager = getDefaultSessionManager();
          sessionManager.writeToFull(sessionKey, { role: "tool", content: textContent, timestamp: Date.now(), sessionKey }).catch(() => {});
          sessionManager.writeToClean(sessionKey, { role: "tool", content: synthetic, timestamp: Date.now(), sessionKey }).catch(() => {});
          gcDebug(api.logger, `[GuardClaw] S3 tool result replaced with synthesis (tool=${ctx.toolName ?? "unknown"})`);
          const modified = replaceMessageText(msg, synthetic);
          if (modified) return { message: modified };
        }
        // No stash (synthesis failed or wasn't run) — fall through to redaction
      }

      const redacted = redactForCleanTranscript(textContent, getLiveConfig().redaction);
      const wasRedacted = redacted !== textContent;

      if (detectedSensitive || wasRedacted || wasPrivateBefore) {
        const sessionManager = getDefaultSessionManager();
        sessionManager.writeToFull(sessionKey, {
          role: "tool", content: textContent, timestamp: Date.now(), sessionKey,
        }).catch(() => {});
        sessionManager.writeToClean(sessionKey, {
          role: "tool", content: wasRedacted ? redacted : textContent, timestamp: Date.now(), sessionKey,
        }).catch(() => {});
      }

      if (wasRedacted) {
        if (!detectedSensitive) markSessionAsPrivate(sessionKey, "S2");
        gcDebug(api.logger, `[GuardClaw] PII-redacted tool result for transcript (tool=${ctx.toolName ?? "unknown"})`);
        const modified = replaceMessageText(msg, redacted);
        if (modified) return { message: modified };
      }

      // ── Sync LLM detection via worker thread ──
      // Rules cover keywords/regex but miss semantic sensitivity.
      // synckit blocks the main thread (via Atomics.wait) for the LLM
      // inference on a Worker, letting us use the result before returning.
      // Timeout (20s) gracefully falls back to rules-only result.
      //
      // IMPORTANT: Skip when the session is ALREADY marked private (S2/S3).
      // The LLM can only escalate — if we're already applying S2 redaction,
      // the sync block adds 10-20s of event-loop freeze per tool result
      // with no meaningful security gain.  This prevents the gateway from
      // going unresponsive during multi-tool-call turns.
      const skipSyncLlm = wasPrivateBefore || detectedSensitive;
      if (privacyConfig.localModel?.enabled && ruleCheck.level !== "S3" && !skipSyncLlm) {
        const llmResult = syncDetectByLocalModel(
          { checkpoint: "onToolCallExecuted", toolName: ctx.toolName, toolResult: textContent, sessionKey },
          privacyConfig,
        );

        if (llmResult.level !== "S1" && llmResult.levelNumeric > ruleCheck.levelNumeric) {
          // LLM-detected S3: PII redaction below will prevent the raw content
          // from reaching the cloud model (sync hook blocks). Model routing
          // cannot change mid-turn, so session marking stays at S2.
          const llmEffective = llmResult.level === "S3" ? "S2" as const : llmResult.level;
          trackSessionLevel(sessionKey, llmResult.level); // audit: true level
          if (!detectedSensitive) {
            markSessionAsPrivate(sessionKey, llmEffective);
          }
          recordDetection(sessionKey, llmResult.level, "onToolCallExecuted", llmResult.reason);
          updateGuardclawStats(llmResult.level).catch(() => {});
          if (llmResult.level === "S3") {
            api.logger.warn(
              `[GuardClaw] LLM elevated tool result to S3 — PII redacted before reaching cloud model. ` +
              `tool=${ctx.toolName ?? "unknown"}, reason=${llmResult.reason ?? "semantic"}`,
            );
          } else {
            gcDebug(api.logger, `[GuardClaw] LLM elevated tool result to ${llmResult.level} (tool=${ctx.toolName ?? "unknown"}, reason=${llmResult.reason ?? "semantic"})`);
          }

          // Use the snapshot taken before detection: if the turn wasn't
          // already private AND rules/regex didn't write above, the LLM
          // is the first to detect — dual-write here.
          if (!detectedSensitive && !wasRedacted && !wasPrivateBefore) {
            const sessionManager = getDefaultSessionManager();
            const ts = Date.now();
            sessionManager.writeToFull(sessionKey, { role: "tool", content: textContent, timestamp: ts, sessionKey }).catch(() => {});
            sessionManager.writeToClean(sessionKey, { role: "tool", content: redacted, timestamp: ts, sessionKey }).catch(() => {});
          }

          // S3 at persist time: redact before the result enters the model
          // context and the persisted transcript.
          if (llmResult.level === "S3") {
            const s3Redacted = wasRedacted ? redacted : redactForCleanTranscript(textContent, getLiveConfig().redaction);
            const modified = replaceMessageText(msg, s3Redacted);
            if (modified) return { message: modified };
          }
        }
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in tool_result_persist hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 6: before_message_write — Dual history persistence + sanitize transcript
  // =========================================================================
  api.on("before_message_write", (event, ctx) => {
    try {
      const sessionKey = ctx.sessionKey ?? "";
      if (!sessionKey) return;

      const msg = event.message;
      if (!msg) return;

      const role = (msg as { role?: string }).role ?? "";
      const pending = getPendingDetection(sessionKey);

      // ── Dual session history persistence ──
      // Persist every message (user, assistant, system) to full/clean tracks
      // when the session is private.  Tool messages are handled separately
      // in tool_result_persist (Hook 5) to avoid double-writes.
      //
      // Also persist when pending detection is S3: Guard Agent is physically
      // isolated so the main session isn't marked private, but we still want
      // the S3 user message recorded (original → full, placeholder → clean)
      // for audit purposes.
      const needsDualHistory = isSessionMarkedPrivate(sessionKey) || (pending?.level === "S3") || isActiveLocalRouting(sessionKey);
      if (needsDualHistory && role !== "tool") {
        const sessionManager = getDefaultSessionManager();
        const msgText = extractMessageText(msg);
        const ts = Date.now();

        if (role === "user" && pending && pending.level !== "S1") {
          // S2/S3 user message: original content → full, sanitized → clean
          const original = pending.originalPrompt ?? msgText;
          sessionManager.writeToFull(sessionKey, {
            role: "user", content: original, timestamp: ts, sessionKey,
          }).catch((err) => {
            console.error("[GuardClaw] Failed to persist user message to full history:", err);
          });
          const cleanContent = pending.level === "S3"
            ? buildMainSessionPlaceholder("S3")
            : (pending.desensitized ?? msgText);
          sessionManager.writeToClean(sessionKey, {
            role: "user", content: cleanContent, timestamp: ts, sessionKey,
          }).catch((err) => {
            console.error("[GuardClaw] Failed to persist user message to clean history:", err);
          });
        } else if (msgText) {
          if (role === "assistant" && isActiveLocalRouting(sessionKey)) {
            // Local model response may contain echoed PII — write original
            // to full track, PII-redacted version to clean track.
            const redacted = redactForCleanTranscript(msgText, getLiveConfig().redaction);
            sessionManager.writeToFull(sessionKey, {
              role: "assistant", content: msgText, timestamp: ts, sessionKey,
            }).catch((err) => {
              console.error("[GuardClaw] Failed to persist assistant message to full history:", err);
            });
            sessionManager.writeToClean(sessionKey, {
              role: "assistant", content: redacted, timestamp: ts, sessionKey,
            }).catch((err) => {
              console.error("[GuardClaw] Failed to persist assistant message to clean history:", err);
            });
          } else {
            // System / S1-user / non-local-routing assistant messages:
            // persistMessage handles guard-agent filtering (guard → full only, others → both).
            sessionManager.persistMessage(sessionKey, {
              role: (role as SessionMessage["role"]) || "assistant",
              content: msgText, timestamp: ts, sessionKey,
            }).catch((err) => {
              console.error("[GuardClaw] Failed to persist message to dual history:", err);
            });
          }
        }
      }

      // ── Guard session assistant responses ──────────────────────────────
      // The guard agent must never echo raw Keychain secret values.  Even
      // though guard session messages are filtered from clean.jsonl by
      // isGuardAgentMessage(), we redact tracked secrets from the guard's
      // full.jsonl transcript as a defense-in-depth measure.
      if (role === "assistant" && isVerifiedGuardSession(sessionKey)) {
        const assistantText = extractMessageText(msg);
        if (assistantText && assistantText.length >= 4) {
          // First: redact tracked Keychain secrets
          const secretRedacted = redactTrackedSecrets(sessionKey, assistantText);
          // Then: redact general PII patterns
          const fullyRedacted = redactSensitiveInfo(secretRedacted, getLiveConfig().redaction);
          if (fullyRedacted !== assistantText) {
            gcDebug(api.logger, "[GuardClaw] Redacted secrets/PII from guard session assistant response");
            return { message: { ...(msg as Record<string, unknown>), content: [{ type: "text", text: fullyRedacted }] } };
          }
        }
        return;
      }

      // ── PII-redact assistant responses from local model ──
      // When S3 data is processed locally the model may echo back PII
      // (e.g. "Your ID 310101... is valid"). Redact before entering the
      // main transcript so subsequent cloud turns don't see raw PII.
      if (role === "assistant" && isActiveLocalRouting(sessionKey)) {
        const assistantText = extractMessageText(msg);
        if (assistantText && assistantText.length >= 10) {
          const redacted = redactForCleanTranscript(assistantText, getLiveConfig().redaction);
          if (redacted !== assistantText) {
            gcDebug(api.logger, "[GuardClaw] PII-redacted local model response before transcript write");
            return { message: { ...(msg as Record<string, unknown>), content: [{ type: "text", text: redacted }] } };
          }
        }
      }

      // ── Response scanning — cloud assistant responses ───────────────────────
      // Scans for secrets/PII echoed in cloud model responses (e.g. API keys
      // accidentally included in generated code or explanations).
      // Only applies to non-guard, non-local-routing sessions.
      if (role === "assistant" && !isVerifiedGuardSession(sessionKey) && !isActiveLocalRouting(sessionKey)) {
        const scanCfg = getLiveConfig().responseScanning;
        if (scanCfg?.enabled) {
          const assistantText = extractMessageText(msg);
          if (assistantText && assistantText.length >= 20) {
            const result = scanResponse(assistantText, scanCfg);
            if (result.hit) {
              api.logger.warn(`[GuardClaw] Response scan hit: ${result.reason} (session=${sessionKey})`);
              fireWebhooks("response_scan_hit", { sessionKey, reason: result.reason, details: { matches: result.matches.join(", ") } }, getLiveConfig().webhooks ?? []);
              if (result.action === "block") {
                return { message: { ...(msg as Record<string, unknown>), content: [{ type: "text", text: "[GuardClaw: Response blocked — contained sensitive content. Use a local model session to work with sensitive data.]" }] } };
              }
              if (result.action === "redact" && result.redacted !== undefined) {
                gcDebug(api.logger, `[GuardClaw] Response scan: redacted ${result.matches.join(", ")} from cloud response`);
                return { message: { ...(msg as Record<string, unknown>), content: [{ type: "text", text: result.redacted }] } };
              }
            }
          }
        }
      }

      // ── Sanitize user messages for session transcript ──
      if (role !== "user") return;
      if (!pending || pending.level === "S1") return;

      if (pending.level === "S3") {
        consumeDetection(sessionKey);
        return { message: { ...msg, content: [{ type: "text", text: buildMainSessionPlaceholder("S3") }] } };
      }
      if (pending.level === "S2" && pending.desensitized) {
        consumeDetection(sessionKey);
        return { message: { ...msg, content: [{ type: "text", text: pending.desensitized }] } };
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_message_write hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 7: session_end — Memory sync
  // =========================================================================
  api.on("session_end", async (event, ctx) => {
    try {
      const sessionKey = event.sessionKey ?? ctx.sessionKey;
      if (!sessionKey) return;

      // GCF-026: Await any pending fire-and-forget memory writes before syncing.
      await awaitPendingMemoryWrites(sessionKey, api.logger);

      const wasPrivate = isSessionMarkedPrivate(sessionKey);
      api.logger.info(`[GuardClaw] ${wasPrivate ? "private" : "cloud"} session ${sessionKey} ended. Syncing memory…`);

      const memMgr = getDefaultMemoryManager();
      const privacyConfig = getLiveConfig();
      await memMgr.syncAllMemoryToClean(privacyConfig);

      clearSessionState(sessionKey);
      clearSessionSecrets(sessionKey); // Free any in-memory Keychain secret values
      clearBehavioralSession(sessionKey); // Free behavioral log in-memory buffers
      deregisterGuardSession(sessionKey); // #12: clean up registry entry for guard subsessions

      const collector = getGlobalCollector();
      if (collector) await collector.flush();
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in session_end hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 8: after_compaction — Full memory sync
  // =========================================================================
  api.on("after_compaction", async (_event, ctx) => {
    try {
      if (ctx.workspaceDir) _cachedWorkspaceDir = ctx.workspaceDir;
      const memMgr = getDefaultMemoryManager();
      const privacyConfig = getLiveConfig();
      await memMgr.syncAllMemoryToClean(privacyConfig);
      gcDebug(api.logger, "[GuardClaw] Memory synced after compaction");
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in after_compaction hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 9: llm_output — Token usage tracking
  // =========================================================================
  api.on("llm_output", async (event, ctx) => {
    try {
      const sessionKey = ctx.sessionKey ?? event.sessionId ?? "";
      const provider = event.provider ?? "unknown";
      const model = event.model ?? "unknown";

      const collector = getGlobalCollector();
      collector?.record({
        sessionKey,
        provider,
        model,
        source: "task",
        usage: event.usage,
      });

      const liveConfig = getLiveConfig();

      // ── Budget guard — record cost, check post-request thresholds ─────────
      const budgetCfg = liveConfig.budget;
      if (budgetCfg?.enabled && event.usage) {
        const cost = calculateCost(model, { input: event.usage.input, output: event.usage.output }, liveConfig.modelPricing ?? {});
        if (cost > 0) {
          recordCost(cost);
          // Check if this request tipped us over the warning threshold
          // (the pre-request check in before_model_resolve already handles exceeded/block;
          // this catches the case where a single large response crosses warn% mid-session)
          const status = checkBudget(budgetCfg);
          if (status.warning && !status.exceeded) {
            const msg = `Budget at ${Math.round((status.dailyCost / (status.dailyCap ?? Infinity)) * 100)}% daily / ${Math.round((status.monthlyCost / (status.monthlyCap ?? Infinity)) * 100)}% monthly`;
            fireWebhooks("budget_warning", { sessionKey, reason: msg, details: { dailyCost: status.dailyCost, monthlyCost: status.monthlyCost } }, liveConfig.webhooks ?? []);
          }
        }
      }
      const origin =
        provider === "guardclaw-privacy"
          ? "cloud"
          : isLocalProvider(provider, liveConfig.localProviders)
            ? "local"
            : "cloud";
      const reason =
        provider === "guardclaw-privacy"
          ? "guardclaw_proxy_to_cloud"
          : origin === "local"
            ? "local_provider"
            : "provider_not_local";

      recordFinalReply({
        sessionKey,
        provider,
        model,
        usage: event.usage,
        extraLocalProviders: liveConfig.localProviders,
        originHint: origin,
        reasonHint: reason,
      });

      // Freeze the current loop snapshot once a final reply is emitted.
      finalizeLoop(sessionKey);
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in llm_output hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 10: before_reset — Full memory sync before session clear
  // =========================================================================
  api.on("before_reset", async (_event, ctx) => {
    try {
      if (ctx.workspaceDir) _cachedWorkspaceDir = ctx.workspaceDir;
      // GCF-026: Await any pending fire-and-forget memory writes before syncing.
      const sessionKey = ctx.sessionKey ?? "";
      if (sessionKey) await awaitPendingMemoryWrites(sessionKey, api.logger);
      const memMgr = getDefaultMemoryManager();
      const privacyConfig = getLiveConfig();
      await memMgr.syncAllMemoryToClean(privacyConfig);
      gcDebug(api.logger, "[GuardClaw] Memory synced before reset");
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_reset hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 11: message_sending — Outbound message guard (via pipeline)
  // =========================================================================
  api.on("message_sending", async (event, ctx) => {
    try {
      const { content, to } = event;
      if (!content?.trim()) return;

      const privacyConfig = getLiveConfig();
      if (!privacyConfig.enabled) return;

      // ── Operator passthrough (channel-scoped) ──────────────────────────────
      // Only bypass redaction if the recipient is explicitly trusted for THIS channel.
      // This prevents accidentally leaking secrets to a different Discord server
      // if OpenClaw ever gets added to multiple servers.
      //
      // Check two sources:
      // 1. Explicit guardclaw.json operatorPassthrough (admin override)
      // 2. OpenClaw's own channel.allowFrom / channel.dmAllowFrom (implicit trust)
      const explicitOperators: string[] = (privacyConfig as Record<string, unknown>).operatorPassthrough as string[] ?? [];
      
      // For now, only use explicit operator list to avoid reading openclaw.json
      // on every message. If you want implicit trust, set operatorPassthrough
      // explicitly in guardclaw.json for your specific user ID.
      // (Auto-discovery happens at startup but is now disabled for safety.)
      
      if (explicitOperators.length > 0 && to && explicitOperators.includes(to)) {
        api.logger.info(`[GuardClaw] Operator passthrough — skipping redaction for trusted recipient: ${to}`);
        return;
      }

      // Skip redaction for channel messages (not DMs) — outbound channel posts
      // are not going to a cloud LLM, they're going to users. Redacting them
      // causes false positives (e.g. @mentions, package names, URLs get mangled).
      // Only apply redaction to DM-style messages (numeric user IDs).
      if (to && (to.startsWith("channel:") || to.startsWith("#") || to === "channel")) {
        api.logger.info(`[GuardClaw] Channel message — skipping outbound redaction for: ${to}`);
        return;
      }

      const pipeline = getGlobalPipeline();
      if (!pipeline) return;

      const sessionKey = ctx.sessionKey ?? "";

      // Redact any in-memory tracked Keychain secrets before the message leaves (#14)
      let outboundContent = content;
      const secretRedacted = redactTrackedSecrets(sessionKey, outboundContent);
      if (secretRedacted !== outboundContent) {
        api.logger.warn(`[GuardClaw] Redacted tracked secret(s) from outbound message (session=${sessionKey})`);
        outboundContent = secretRedacted;
      }

      const decision = await pipeline.run(
        "onUserMessage",
        { checkpoint: "onUserMessage", message: outboundContent, sessionKey },
        getPipelineConfig(),
      );

      if (decision.level === "S3" || decision.action === "block") {
        api.logger.warn("[GuardClaw] BLOCKED outbound message: S3/block detected");
        return { cancel: true };
      }
      if (decision.level === "S2") {
        const desenResult = await desensitizeWithLocalModel(outboundContent, privacyConfig, ctx.sessionKey);
        if (desenResult.failed) {
          api.logger.warn("[GuardClaw] S2 desensitization failed — cancelling outbound message to prevent PII leak");
          return { cancel: true };
        }
        return { content: desenResult.desensitized };
      }
      // S1: return the secret-redacted content if it changed
      if (outboundContent !== content) return { content: outboundContent };
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in message_sending hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 12: before_agent_start — Subagent guard (via pipeline)
  // =========================================================================
  api.on("before_agent_start", async (event, ctx) => {
    try {
      const { prompt } = event;
      const sessionKey = ctx.sessionKey ?? "";
      if (!sessionKey.includes(":subagent:") || !prompt?.trim()) return;

      const privacyConfig = getLiveConfig();
      if (!privacyConfig.enabled) return;

      const pipeline = getGlobalPipeline();
      if (!pipeline) return;

      const decision = await pipeline.run(
        "onUserMessage",
        { checkpoint: "onUserMessage", message: prompt, sessionKey, agentId: ctx.agentId },
        getPipelineConfig(),
      );

      // S3 / block: route the subagent to a local model instead of
      // modifying the system prompt.  The cloud model has already seen the
      // prompt text, so altering system instructions is not a reliable
      // security control.  Routing to a local model keeps the data local.
      if (decision.level === "S3" || decision.action === "block") {
        const guardCfg = getGuardAgentConfig(privacyConfig);
        const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
        const provider = guardCfg?.provider ?? defaultProvider;
        const model = guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "qwen/qwen3-30b-a3b-2507";
        api.logger.info(`[GuardClaw] Subagent ${decision.level} — routing to ${provider}/${model}`);
        return {
          providerOverride: provider,
          modelOverride: model,
        };
      }
      if (decision.level === "S2") {
        const privacyCfg = getLiveConfig();
        const desenResult = await desensitizeWithLocalModel(prompt, privacyCfg, sessionKey);
        if (desenResult.failed) {
          const guardCfg = getGuardAgentConfig(privacyCfg);
          const fallbackProvider = privacyCfg.localModel?.provider ?? "ollama";
          const provider = guardCfg?.provider ?? fallbackProvider;
          const model = guardCfg?.modelName ?? privacyCfg.localModel?.model ?? "qwen/qwen3-30b-a3b-2507";
          api.logger.warn(`[GuardClaw] Subagent S2 desensitization failed — routing to local ${provider}/${model}`);
          return { providerOverride: provider, modelOverride: model };
        }
        api.logger.info("[GuardClaw] Subagent S2 — prompt desensitized before forwarding");
        return { prompt: desenResult.desensitized };
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_agent_start hook: ${String(err)}`);
    }
  });

  // =========================================================================
  // Hook 13: message_received — Stash sender ID + observational logging
  // =========================================================================
  api.on("message_received", async (event, ctx) => {
    try {
      const privacyConfig = getLiveConfig();
      if (!privacyConfig.enabled) return;
      api.logger.info?.(`[GuardClaw] Message received from ${event.from ?? "unknown"}`);

      // Stash the sender ID now, while the raw envelope is still accessible.
      // before_model_resolve fires next but by then the Discord envelope JSON
      // has been stripped from `prompt`, so sender_id would be MISSING.
      const msgText = String((event as unknown as Record<string, unknown>).message ?? (event as unknown as Record<string, unknown>).content ?? "");
      // 1. Parse from raw Discord envelope JSON in message text (most reliable)
      const envelopeMatch = msgText.match(/"sender_id"\s*:\s*"(\d+)"/);
      // 2. Fallback: event.metadata?.senderId
      // 3. Fallback: event.from if it's a numeric snowflake
      const senderId =
        envelopeMatch?.[1] ??
        (event.metadata?.senderId as string | undefined) ??
        (typeof event.from === "string" && /^\d+$/.test(event.from) ? event.from : undefined);
      if (senderId && ctx.channelId) {
        setLastSenderId(ctx.channelId, senderId);
        api.logger.debug?.(`[GuardClaw S0] Stashed senderId=${senderId} for channel=${ctx.channelId}`);
      }
    } catch { /* observational only */ }
  });

  api.logger.info("[GuardClaw] All hooks registered (13 hooks, pipeline-driven)");
}

// ==========================================================================
// Helpers
// ==========================================================================

/** Tools that execute shell commands and produce stdout that may contain secrets. */
const EXEC_TOOL_NAMES = new Set(["exec", "shell", "system.run", "run_command", "execute", "bash", "terminal"]);

function isExecTool(toolName: string): boolean {
  return EXEC_TOOL_NAMES.has(toolName) || toolName.startsWith("exec") || toolName.includes("shell");
}

/**
 * Check if an exec command is likely to produce secrets in stdout.
 * Returns the matched risk category string, or null if safe.
 *
 * This is a pre-screening heuristic — it blocks commands BEFORE execution
 * rather than trying to scrub output after (which OpenClaw doesn't support).
 */
const HIGH_RISK_EXEC_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  // Reading credential/secret files
  { pattern: /cat\s+.*\.(env|pem|key|p12|pfx|jks|keystore)\b/i, reason: "reads credential file" },
  { pattern: /cat\s+.*\/(credentials|secrets|password|token)\b/i, reason: "reads secret file" },
  { pattern: /cat\s+.*(\.aws\/credentials|\.ssh\/|id_rsa|id_ed25519)/i, reason: "reads SSH/AWS credentials" },
  { pattern: /cat\s+.*\/etc\/(shadow|passwd|master\.passwd)/i, reason: "reads system auth files" },
  // Dumping environment variables with secrets (any variation of env command)
  { pattern: /\benv\b/, reason: "dumps environment variables" },
  { pattern: /\bprintenv\b/i, reason: "dumps environment variables" },
  { pattern: /\bset\s*\|/i, reason: "dumps shell variables" },
  { pattern: /export\s+-p\b/i, reason: "dumps exported variables" },
  // macOS keychain access
  { pattern: /security\s+find-(generic|internet)-password/i, reason: "reads macOS keychain" },
  { pattern: /security\s+dump-keychain/i, reason: "dumps macOS keychain" },
  // Explicit secret/key dumping
  { pattern: /\bgrep\b.*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)/i, reason: "greps for secrets" },
  { pattern: /\bawk\b.*(?:password|secret|token|key)/i, reason: "extracts secrets" },
  // Terraform/cloud state with secrets
  { pattern: /terraform\s+(?:output|state\s+show|state\s+pull)/i, reason: "reads terraform state (may contain secrets)" },
  // Database credential access
  { pattern: /\bmysqldump\b.*--password/i, reason: "MySQL dump with password" },
  { pattern: /\bpg_dump\b.*--password/i, reason: "PostgreSQL dump with password" },
  // Kubernetes secrets
  { pattern: /kubectl\s+get\s+secret/i, reason: "reads Kubernetes secrets" },
  { pattern: /kubectl.*-o\s+(?:json|yaml).*secret/i, reason: "dumps Kubernetes secrets" },
  // Docker inspect with env vars
  { pattern: /docker\s+inspect.*--format.*\.Env/i, reason: "reads container env vars" },
  // GPG/age decryption
  { pattern: /\b(?:gpg|age)\s+(?:-d|--decrypt)\b/i, reason: "decrypts secrets" },
  // SOPS decryption
  { pattern: /\bsops\s+(?:-d|--decrypt|exec-env|exec-file)\b/i, reason: "decrypts SOPS secrets" },
  // Base64 decode of files (common way to decode embedded secrets)
  { pattern: /base64\s+(?:-d|--decode)\s+.*\.(env|pem|key|txt|conf|cfg)\b/i, reason: "decodes potentially encoded secrets" },
  { pattern: /base64\s+(?:-d|--decode)\s+.*\/(secret|credential|password|token|key)\b/i, reason: "decodes secret file" },
  // Clipboard dump (may contain copied passwords)
  { pattern: /\bpbpaste\b/i, reason: "reads clipboard (may contain copied secrets)" },
  // Shell history grep for secrets
  { pattern: /history\s*\|?\s*grep\s+.*(?:password|passwd|secret|token|key|api|auth)/i, reason: "searches shell history for secrets" },
  // strings extraction on binaries (used to extract embedded creds)
  { pattern: /\bstrings\b.*\/(secret|credential|password|token|key|\.env)\b/i, reason: "extracts strings from file (may expose embedded secrets)" },
  // curl/wget with inline credentials
  { pattern: /\bcurl\b.*(?:-u\s+\S+:\S+|--user\s+\S+:\S+)/i, reason: "curl with inline credentials" },
  { pattern: /\bcurl\b.*(?:Authorization:\s*Bearer|Authorization:\s*Basic)/i, reason: "curl with auth header containing credentials" },
  { pattern: /\bwget\b.*(?:--password|--http-password|--ftp-password)/i, reason: "wget with inline password" },
];

function isHighRiskExecCommand(command: string): string | null {
  const normalized = command.trim();
  for (const { pattern, reason } of HIGH_RISK_EXEC_PATTERNS) {
    if (pattern.test(normalized)) return reason;
  }
  return null;
}

/**
 * Network-capable CLI tools blocked inside guard (S3) bash commands.
 *
 * Scanned against the raw command string, which naturally covers $(...) and
 * backtick sub-expressions — the literal tool name is still present regardless
 * of how it is quoted or nested.
 */
// GCF-015: Expanded network exfiltration patterns for guard bash sessions.
// GCF-016: eval/exec/source are blocked entirely — they enable arbitrary code
//          execution that bypasses all static pattern checks.
const GUARD_BASH_NETWORK_PATTERNS: Array<{ pattern: RegExp; tool: string }> = [
  { pattern: /\bcurl\b/i,                                             tool: "curl" },
  { pattern: /\bwget\b/i,                                             tool: "wget" },
  { pattern: /(?:^|\s)ncat?\b/m,                                      tool: "nc/ncat" },
  { pattern: /\bnetcat\b/i,                                           tool: "netcat" },
  { pattern: /\bsocat\b/i,                                            tool: "socat" },
  { pattern: /\bssh\s/i,                                              tool: "ssh" },
  { pattern: /\bscp\s/i,                                              tool: "scp" },
  { pattern: /\bsftp\s/i,                                             tool: "sftp" },
  { pattern: /\brsync\s+\S*@/i,                                       tool: "rsync (remote)" },
  { pattern: /\bftp\s/i,                                              tool: "ftp" },
  { pattern: /\btelnet\b/i,                                           tool: "telnet" },
  { pattern: /\bopenssl\s+s_client\b/i,                               tool: "openssl s_client" },
  { pattern: /\/dev\/tcp\//,                                           tool: "/dev/tcp" },
  { pattern: /\bpython[23]?\b[\s\S]*?-c[\s\S]*?socket/i,             tool: "python socket" },
  { pattern: /\bnode\b[\s\S]*?-e[\s\S]*?(?:http|https|net|tls)\b/i, tool: "node net" },
  { pattern: /\bperl\b[\s\S]*?-e[\s\S]*?socket/i,                    tool: "perl socket" },
  // GCF-015: Cloud CLI tools — each can exfiltrate files to attacker-controlled storage
  { pattern: /\baws\s/i,                                               tool: "aws-cli" },
  { pattern: /\bgsutil\s/i,                                            tool: "gsutil" },
  { pattern: /\baz\s/i,                                                tool: "azure-cli" },
  { pattern: /\bdocker\s+push\b/i,                                     tool: "docker push" },
  // git push with a remote URL (not just 'git push origin' — but catch URL forms)
  { pattern: /\bgit\s+(?:push|remote\s+add)\s+(?:\S+\s+)?https?:\/\//i, tool: "git push (url)" },
  // Scripting language one-liners that make network calls
  { pattern: /\bruby\s+-e\b/i,                                         tool: "ruby -e" },
  { pattern: /\bphp\s+-r\b/i,                                          tool: "php -r" },
  // DNS exfiltration via nslookup/dig
  { pattern: /\bnslookup\b/i,                                          tool: "nslookup" },
  { pattern: /\bdig\s/i,                                               tool: "dig" },
  // GCF-016: Obfuscation primitives — block entirely to prevent bypass of all above patterns
  { pattern: /\beval\b/i,                                              tool: "eval (obfuscation)" },
  { pattern: /\bexec\b/i,                                              tool: "exec (obfuscation)" },
  { pattern: /\bsource\b/i,                                            tool: "source (obfuscation)" },
  { pattern: /\b\.\s+[^\s]/,                                           tool: "source-dot (obfuscation)" },
];

/**
 * Returns the matched tool name if the bash command could make an outbound
 * network connection, or null if no network tool was detected.
 * (#1 fix) Prevents exfiltration via bash in guard sessions.
 */
function isGuardNetworkCommand(command: string): string | null {
  for (const { pattern, tool } of GUARD_BASH_NETWORK_PATTERNS) {
    if (pattern.test(command)) return tool;
  }
  return null;
}

/**
 * GCF-030: Detect tool-noise — short, non-sensitive tool status output that
 * should bypass the heavy S2 pipeline (rules, injection heuristics, sync LLM,
 * taint tracking, proxy forwarding) to prevent connection storms.
 *
 * Returns true when the text is overwhelmingly likely to be benign status.
 * Conservative: any doubt → returns false → full pipeline runs.
 */
const TOOL_NOISE_PATTERNS = /^\s*(?:[\u2713\u2714\u2715\u2716\u2022\u25cf\u25cb•·\-\*]\s*)?(?:ok|done|success|created|updated|deleted|wrote|saved|started|stopped|finished|completed|running|exited?\s*(?:code\s*)?\d*|true|false|null|undefined|\d+(?:\.\d+)?\s*(?:ms|s|sec|bytes?|[kmg]b)?|no\s+(?:results?|matches?|changes?|output)|\[\d+\/\d+\]|\d+\s+files?|empty|skipped|unchanged|passed|failed|error|warning|\{\}|\[\]|\s*)$/i;

const TOOL_NOISE_TOOL_NAMES = new Set([
  "list_dir", "list_directory", "ls", "search_files", "find_files",
  "task_status", "task_progress", "get_status", "ping", "health_check",
  "list_sessions", "list_agents",
]);

// Words that signal potentially sensitive content — never treat as noise
const SENSITIVE_WORDS_RE = /\b(?:password|passphrase|passwd|secret|token|credential|api.?key|private.?key|auth|ssn|salary|payroll|diagnosis|diagnos|patient|medical|prescription|bank|account|routing|bsb|acn|abn|tfn|medicare|ssn|license|passport|encrypt|decrypt)\b/i;

function isToolNoise(text: string, toolName?: string): boolean {
  const trimmed = text.trim();
  // Empty or whitespace-only
  if (!trimmed) return true;
  // Known status-only tools
  if (toolName && TOOL_NOISE_TOOL_NAMES.has(toolName)) return true;
  // Matches common status patterns ("done", "ok", exit codes, etc.)
  if (TOOL_NOISE_PATTERNS.test(trimmed)) return true;
  // Single-line short output with no PII-indicative characters AND no sensitive words
  if (!trimmed.includes("\n") && trimmed.length < 80
      && !/[@\d]{4,}|\b\d{3}[-.]\d{3}/.test(trimmed)
      && !SENSITIVE_WORDS_RE.test(trimmed)) return true;
  return false;
}

function shouldSkipMessage(msg: string): boolean {
  if (msg.includes("[REDACTED:") || msg.startsWith("[SYSTEM]")) return true;
  if (/^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}/.test(msg)) return true;
  // Skip pure system events with no user content
  if (msg.includes("<<<EXTERNAL_UNTRUSTED_CONTENT") && msg.includes("Untrusted channel metadata") && !extractUserContent(msg)) return true;
  return false;
}

/**
 * Strip OpenClaw's Discord thread context prefix from a message before passing
 * to injection detection.  The prefix looks like:
 *   [Thread starter - for context]\n🤖 claude\n\nConversation info: ...
 *
 * DeBERTa sees "🤖 claude" and the JSON role labels and classifies the whole
 * thing as a role-override injection with very high confidence — a false positive
 * on OpenClaw's own envelope format.
 *
 * If the message has a Discord envelope (conversation_label / sender_id),
 * extractUserContent already handles stripping. This function handles the
 * case where those markers are absent (e.g. thread-starter messages that
 * don't carry the full JSON envelope).
 */
function stripThreadContextPrefix(msg: string): string {
  // Pattern: starts with [Thread starter - for context] up to the actual user text
  // The user text follows the last ```\n\n block, or after the Sender: block
  if (!msg.startsWith("[Thread starter")) return msg;
  const lastBlockEnd = msg.lastIndexOf("```\n\n");
  if (lastBlockEnd !== -1) {
    const after = msg.slice(lastBlockEnd + 5).trim();
    if (after.length > 0) return after;
  }
  // Fallback: drop everything before the last double-newline that follows a ``` close
  const match = msg.match(/```\s*\n+([\s\S]+)$/);
  if (match?.[1]?.trim()) return match[1].trim();
  return msg;
}

/**
 * Extract the actual user message content from OpenClaw envelope format.
 * OpenClaw wraps Discord/iMessage/Telegram messages with JSON metadata blocks.
 * This extracts just the user's text for injection detection.
 */
function extractUserContent(msg: string): string {
  // If no envelope markers, return as-is
  if (!msg.includes("conversation_label") && !msg.includes("sender_id")) {
    return msg;
  }
  
  // Pattern 1: Content after the last ```json...``` block
  // Messages have structure: [Thread starter...]\n\nConversation info:\n```json\n{...}\n```\n\nSender:\n```json\n{...}\n```\n\n<actual message>
  const lastJsonBlockEnd = msg.lastIndexOf("```\n\n");
  if (lastJsonBlockEnd !== -1) {
    const afterBlock = msg.slice(lastJsonBlockEnd + 5).trim();
    if (afterBlock.length > 0) return afterBlock;
  }
  
  // Pattern 2: Content after Sender metadata block (alternate format)
  const senderBlockMatch = msg.match(/```\s*\n\s*\n([^`]+)$/);
  if (senderBlockMatch && senderBlockMatch[1].trim()) {
    return senderBlockMatch[1].trim();
  }
  
  // Pattern 3: Just find the last non-JSON paragraph
  const paragraphs = msg.split(/\n\n+/);
  for (let i = paragraphs.length - 1; i >= 0; i--) {
    const p = paragraphs[i].trim();
    // Skip JSON blocks, metadata markers, thread starters
    if (p.startsWith("```") || p.startsWith("{") || p.startsWith("[Thread") || 
        p.includes("conversation_label") || p.includes("sender_id") ||
        p.startsWith("Conversation info") || p.startsWith("Sender")) {
      continue;
    }
    if (p.length > 0) return p;
  }
  
  return "";
}

/**
 * Extract text from an AgentMessage (supports string content and content arrays).
 */
function extractMessageText(msg: unknown): string {
  if (typeof msg === "string") return msg;
  if (!msg || typeof msg !== "object") return "";
  const m = msg as Record<string, unknown>;

  if (typeof m.content === "string") return m.content;

  if (Array.isArray(m.content)) {
    return m.content
      .map((part: unknown) => {
        if (typeof part === "string") return part;
        if (part && typeof part === "object" && typeof (part as Record<string, unknown>).text === "string") {
          return (part as Record<string, unknown>).text as string;
        }
        return "";
      })
      .filter(Boolean)
      .join("\n");
  }

  return "";
}

/**
 * Replace text content in an AgentMessage, preserving the message structure.
 * For content arrays, replaces the FIRST text part in-place and removes
 * subsequent text parts, preserving the original ordering of non-text parts
 * (images, file references, etc.).
 */
function replaceMessageText(msg: unknown, newText: string): unknown | null {
  if (typeof msg === "string") return newText;
  if (!msg || typeof msg !== "object") return null;
  const m = { ...(msg as Record<string, unknown>) };

  if (typeof m.content === "string") {
    return { ...m, content: newText };
  }

  if (Array.isArray(m.content)) {
    let textReplaced = false;
    const newContent: Array<Record<string, unknown>> = [];
    for (const part of m.content as Array<Record<string, unknown>>) {
      if (part && typeof part === "object" && part.type === "text") {
        if (!textReplaced) {
          newContent.push({ type: "text", text: newText });
          textReplaced = true;
        }
      } else {
        newContent.push(part);
      }
    }
    if (!textReplaced) {
      newContent.unshift({ type: "text", text: newText });
    }
    return { ...m, content: newContent };
  }

  return null;
}

// ── Dual-track history injection helper ───────────────────────────────────

/**
 * Load the "delta" between full and clean session histories and format it
 * as conversation context.  Returns null if there is nothing meaningful
 * to inject (e.g. no prior sensitive turns, or dual history is empty).
 */
async function loadDualTrackContext(
  sessionKey: string,
  agentId?: string,
  limit?: number,
): Promise<string | null> {
  try {
    const mgr = getDefaultSessionManager();
    const delta = await mgr.loadHistoryDelta(sessionKey, agentId ?? "main", limit);
    if (delta.length === 0) return null;
    return DualSessionManager.formatAsContext(delta);
  } catch {
    return null;
  }
}

// ── Memory dual-write helpers ─────────────────────────────────────────────

const MEMORY_WRITE_PATTERNS = [
  /^MEMORY\.md$/,
  /^memory\.md$/,
  /^memory\//,
];

function isMemoryWritePath(writePath: string): boolean {
  const rel = writePath.replace(/^\.\//, "");
  return MEMORY_WRITE_PATTERNS.some((p) => p.test(rel));
}

/**
 * After Agent writes to a memory file, dual-write to the other track:
 *   MEMORY.md written → read content → write full to MEMORY-FULL.md, redact to MEMORY.md
 *   memory/X.md written → read → write full to memory-full/X.md, redact to memory/X.md
 */
async function syncMemoryWrite(
  writePath: string,
  workspaceDir: string,
  privacyConfig: PrivacyConfig,
  logger: { info: (msg: string) => void; warn: (msg: string) => void },
  isGuardSession: boolean = false,
): Promise<void> {
  const rel = writePath.replace(/^\.\//, "");
  const absPath = path.isAbsolute(writePath)
    ? writePath
    : path.resolve(workspaceDir, rel);

  let content: string;
  try {
    content = await fs.promises.readFile(absPath, "utf-8");
  } catch {
    return;
  }

  if (!content.trim()) return;

  // Symlink guard (GCF-010): reject symlinks on both source and target paths
  // to prevent pre-planted symlinks from exfiltrating or overwriting arbitrary files.
  try {
    const srcStat = await fs.promises.lstat(absPath);
    if (srcStat.isSymbolicLink()) {
      logger.warn(`[GuardClaw] Memory dual-write blocked — source path is a symlink: ${absPath}`);
      return;
    }
  } catch { /* file doesn't exist yet — that's fine */ }

  // Determine the counterpart path
  let fullRelPath: string;
  if (rel === "MEMORY.md" || rel === "memory.md") {
    fullRelPath = "MEMORY-FULL.md";
  } else if (rel.startsWith("memory/")) {
    fullRelPath = rel.replace(/^memory\//, "memory-full/");
  } else {
    return;
  }

  const fullAbsPath = path.resolve(workspaceDir, fullRelPath);

  // Ensure directory exists for daily memory files
  await fs.promises.mkdir(path.dirname(fullAbsPath), { recursive: true });

  // Symlink guard on destination (GCF-010)
  try {
    const dstStat = await fs.promises.lstat(fullAbsPath);
    if (dstStat.isSymbolicLink()) {
      logger.warn(`[GuardClaw] Memory dual-write blocked — destination path is a symlink: ${fullAbsPath}`);
      return;
    }
  } catch { /* destination doesn't exist yet — that's fine */ }

  // Wrap guard agent content with explicit markers so filterGuardContent
  // can reliably strip it when syncing FULL → CLEAN.
  const fullContent = isGuardSession
    ? `${GUARD_SECTION_BEGIN}\n${content}\n${GUARD_SECTION_END}`
    : content;
  await fs.promises.writeFile(fullAbsPath, fullContent, { encoding: "utf-8", mode: 0o600 });

  // Redact PII and overwrite the clean version
  const memMgr = getDefaultMemoryManager();
  const redacted = await memMgr.redactContentPublic(content, privacyConfig);
  if (redacted !== content) {
    await fs.promises.writeFile(absPath, redacted, { encoding: "utf-8", mode: 0o600 });
    logger.info(`[GuardClaw] Memory dual-write: ${rel} → ${fullRelPath} (redacted clean copy)`);
  } else {
    logger.info(`[GuardClaw] Memory dual-write: ${rel} → ${fullRelPath} (no PII found)`);
  }
}

/**
 * Filter memory_search results: strip results from the wrong memory track.
 * Cloud-bound sessions should not see MEMORY-FULL.md / memory-full/ results.
 * Fully-local sessions should not see MEMORY.md / memory/ results (prefer full).
 */
function filterMemorySearchResults(msg: unknown, useFullTrack: boolean): unknown | null {
  if (!msg || typeof msg !== "object") return null;
  const m = msg as Record<string, unknown>;

  const textContent = extractMessageText(msg);
  if (!textContent) return null;

  try {
    const parsed = JSON.parse(textContent);
    if (!parsed || typeof parsed !== "object") return null;

    const results = (parsed as Record<string, unknown>).results;
    if (!Array.isArray(results)) return null;

    const filtered = results.filter((r: unknown) => {
      if (!r || typeof r !== "object") return true;
      const rPath = String((r as Record<string, unknown>).path ?? "");
      if (useFullTrack) {
        // Fully-local session: exclude clean-track results (prefer full)
        if (rPath === "MEMORY.md" || rPath === "memory.md" || rPath.startsWith("memory/")) {
          return false;
        }
      } else {
        // Cloud-bound session: exclude full-track results
        if (rPath === "MEMORY-FULL.md" || rPath.startsWith("memory-full/")) {
          return false;
        }
      }
      return true;
    });

    if (filtered.length === results.length) return null;

    const newParsed = { ...parsed as Record<string, unknown>, results: filtered };
    const newText = JSON.stringify(newParsed);
    return replaceMessageText(msg, newText);
  } catch {
    return null;
  }
}
