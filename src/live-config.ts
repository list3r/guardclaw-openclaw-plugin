/**
 * GuardClaw Live Config
 *
 * Mutable in-memory config cache that hooks read from at runtime.
 * Updated via:
 *   - Dashboard save  → updateLiveConfig()
 *   - File watcher    → guardclaw.json change auto-reloads
 *
 * The only setting that cannot be hot-reloaded is proxyPort (already bound).
 */

import { readFileSync, watch, type FSWatcher } from "node:fs";
import { readFile, writeFile, rename } from "node:fs/promises";
import { join } from "node:path";
import type { PrivacyConfig, InjectionConfig } from "./types.js";
import { defaultPrivacyConfig, defaultInjectionConfig } from "./config-schema.js";
import { updateInjectionConfig } from "./injection/index.js";

let liveConfig: PrivacyConfig = { ...defaultPrivacyConfig } as PrivacyConfig;
let liveInjectionConfig: InjectionConfig = { ...defaultInjectionConfig };
let configWatcher: FSWatcher | null = null;

/** Shared injection attempt counter — used by both hooks and proxy so cross-layer attempts aggregate.
 *  Value is {count, ts} so entries can be expired after 24 h to prevent unbounded growth. */
const ATTEMPT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
export const injectionAttemptCounts = new Map<string, { count: number; ts: number }>();

/** Track senders currently mid-ban to prevent duplicate concurrent ban operations. */
export const pendingBans = new Set<string>();

// ── Attempt count persistence (#7) ─────────────────────────────────────────
// Path resolved lazily once HOME is known (not available at module load time
// in all environments).
let _attemptCountsPath: string | null = null;

function getAttemptCountsPath(): string {
  if (!_attemptCountsPath) {
    const home = process.env.HOME ?? process.env.USERPROFILE ?? "/tmp";
    _attemptCountsPath = join(home, ".openclaw", "guardclaw-attempt-counts.json");
  }
  return _attemptCountsPath;
}

/**
 * Load persisted injection attempt counts from disk on startup.
 * Prunes entries older than ATTEMPT_TTL_MS so the file doesn't grow unbounded.
 * Non-fatal — silently no-ops if the file is absent or corrupt.
 */
export async function loadInjectionAttemptCounts(): Promise<void> {
  try {
    const raw = await readFile(getAttemptCountsPath(), "utf-8");
    const data = JSON.parse(raw) as Record<string, { count: number; ts: number }>;
    const now = Date.now();
    for (const [id, entry] of Object.entries(data)) {
      if (now - entry.ts < ATTEMPT_TTL_MS) {
        injectionAttemptCounts.set(id, entry);
      }
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "ENOENT") {
      console.warn("[GuardClaw] guardclaw-attempt-counts.json appears corrupt, starting fresh:", String(err));
    }
  }
}

/** Atomically persist the current attempt counts to disk (best-effort). */
async function persistInjectionAttemptCounts(): Promise<void> {
  try {
    const filePath = getAttemptCountsPath();
    const tmp = filePath + ".tmp";
    const data: Record<string, { count: number; ts: number }> = {};
    for (const [id, entry] of injectionAttemptCounts.entries()) {
      data[id] = entry;
    }
    await writeFile(tmp, JSON.stringify(data));
    await rename(tmp, filePath); // atomic on POSIX
  } catch { /* best-effort */ }
}

/** Increment attempt count for a sender (resetting if expired) and return the new count. */
export function recordInjectionAttempt(senderId: string): number {
  const now = Date.now();
  const entry = injectionAttemptCounts.get(senderId);
  const count = (entry && now - entry.ts < ATTEMPT_TTL_MS) ? entry.count + 1 : 1;
  injectionAttemptCounts.set(senderId, { count, ts: now });
  // Persist async — fire-and-forget so the hot path isn't blocked (#7)
  persistInjectionAttemptCounts().catch(() => {});
  return count;
}

/** Initialize live config from the plugin's startup config snapshot. */
export function initLiveConfig(pluginConfig: Record<string, unknown> | undefined): void {
  const userConfig = (pluginConfig?.privacy ?? {}) as PrivacyConfig;
  liveConfig = mergeConfig(userConfig);
  const userInjection = ((pluginConfig?.privacy as Record<string, unknown>)?.injection ?? {}) as InjectionConfig;
  liveInjectionConfig = { ...defaultInjectionConfig, ...userInjection };
  updateInjectionConfig(liveInjectionConfig); // keep injection/index.ts store in sync
}

/**
 * Watch guardclaw.json for external edits and hot-reload into liveConfig.
 * Uses a debounce to avoid reloading multiple times on rapid writes.
 */
export function watchConfigFile(
  configPath: string,
  logger: { info: (msg: string) => void },
): void {
  if (configWatcher) return;
  let debounce: ReturnType<typeof setTimeout> | null = null;
  try {
    configWatcher = watch(configPath, () => {
      if (debounce) clearTimeout(debounce);
      debounce = setTimeout(() => {
        try {
          const raw = JSON.parse(readFileSync(configPath, "utf-8")) as Record<string, unknown>;
          const privacy = (raw.privacy ?? {}) as PrivacyConfig;
          liveConfig = mergeConfig(privacy);
          const injection = ((raw.privacy as Record<string, unknown>)?.injection ?? {}) as InjectionConfig;
          liveInjectionConfig = { ...defaultInjectionConfig, ...injection };
          updateInjectionConfig(liveInjectionConfig); // keep injection/index.ts store in sync
          logger.info("[GuardClaw] guardclaw.json changed — config hot-reloaded");
        } catch (err) {
          console.warn("[GuardClaw] Config reload failed (partial write?) — retaining previous config:", String(err));
        }
      }, 300);
    });
  } catch { /* file may not exist yet — non-fatal */ }
}

/** Get the current live config (mutable, always up-to-date). */
export function getLiveConfig(): PrivacyConfig {
  return liveConfig;
}

/** Get the current live injection config (mutable, always up-to-date). */
export function getLiveInjectionConfig(): InjectionConfig {
  return liveInjectionConfig;
}

/** Hot-update the live config. Called from Dashboard save handler. */
export function updateLiveConfig(patch: Partial<PrivacyConfig>): void {
  liveConfig = mergeConfig({ ...liveConfig, ...patch });
}

// ── GCF-024: guardclaw.json RMW mutex ───────────────────────────────────────
// All read-modify-write operations on guardclaw.json must go through this lock
// so concurrent auto-ban writes from hooks.ts and privacy-proxy.ts don't race.

let _configWriteLock: Promise<void> = Promise.resolve();

/**
 * Serialize all read-modify-write operations on guardclaw.json.
 * Uses Promise-chaining as an in-process async mutex.
 */
export function withConfigWriteLock<T>(fn: () => Promise<T>): Promise<T> {
  let resolve!: () => void;
  const gate = new Promise<void>((r) => { resolve = r; });
  const result = _configWriteLock.then(() => fn()).finally(resolve);
  _configWriteLock = gate;
  return result;
}

/** Hot-update the live injection config. Called after auto-ban. */
export function updateLiveInjectionConfig(patch: Partial<InjectionConfig>): void {
  liveInjectionConfig = { ...liveInjectionConfig, ...patch };
  updateInjectionConfig(liveInjectionConfig); // keep injection/index.ts store in sync
}

function mergeConfig(userConfig: PrivacyConfig): PrivacyConfig {
  return {
    ...defaultPrivacyConfig,
    ...userConfig,
    checkpoints: { ...defaultPrivacyConfig.checkpoints, ...userConfig.checkpoints },
    rules: {
      keywords: { ...defaultPrivacyConfig.rules?.keywords, ...userConfig.rules?.keywords },
      patterns: { ...defaultPrivacyConfig.rules?.patterns, ...userConfig.rules?.patterns },
      tools: {
        S2: { ...defaultPrivacyConfig.rules?.tools?.S2, ...userConfig.rules?.tools?.S2 },
        S3: { ...defaultPrivacyConfig.rules?.tools?.S3, ...userConfig.rules?.tools?.S3 },
      },
    },
    localModel: { ...defaultPrivacyConfig.localModel, ...userConfig.localModel },
    guardAgent: { ...defaultPrivacyConfig.guardAgent, ...userConfig.guardAgent },
    session: { ...defaultPrivacyConfig.session, ...userConfig.session },
    localProviders: [
      ...defaultPrivacyConfig.localProviders,
      ...(userConfig.localProviders ?? []),
    ],
    modelPricing: {
      ...defaultPrivacyConfig.modelPricing,
      ...userConfig.modelPricing,
    },
    redaction: { ...defaultPrivacyConfig.redaction, ...userConfig.redaction },
  } as PrivacyConfig;
}
