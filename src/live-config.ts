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
import type { PrivacyConfig, InjectionConfig } from "./types.js";
import { defaultPrivacyConfig, defaultInjectionConfig } from "./config-schema.js";

let liveConfig: PrivacyConfig = { ...defaultPrivacyConfig } as PrivacyConfig;
let liveInjectionConfig: InjectionConfig = { ...defaultInjectionConfig };
let configWatcher: FSWatcher | null = null;

/** Shared injection attempt counter — used by both hooks and proxy so cross-layer attempts aggregate.
 *  Value is {count, ts} so entries can be expired after 24 h to prevent unbounded growth. */
const ATTEMPT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
export const injectionAttemptCounts = new Map<string, { count: number; ts: number }>();

/** Track senders currently mid-ban to prevent duplicate concurrent ban operations. */
export const pendingBans = new Set<string>();

/** Increment attempt count for a sender (resetting if expired) and return the new count. */
export function recordInjectionAttempt(senderId: string): number {
  const now = Date.now();
  const entry = injectionAttemptCounts.get(senderId);
  const count = (entry && now - entry.ts < ATTEMPT_TTL_MS) ? entry.count + 1 : 1;
  injectionAttemptCounts.set(senderId, { count, ts: now });
  return count;
}

/** Initialize live config from the plugin's startup config snapshot. */
export function initLiveConfig(pluginConfig: Record<string, unknown> | undefined): void {
  const userConfig = (pluginConfig?.privacy ?? {}) as PrivacyConfig;
  liveConfig = mergeConfig(userConfig);
  const userInjection = ((pluginConfig?.privacy as Record<string, unknown>)?.injection ?? {}) as InjectionConfig;
  liveInjectionConfig = { ...defaultInjectionConfig, ...userInjection };
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
          logger.info("[GuardClaw] guardclaw.json changed — config hot-reloaded");
        } catch { /* ignore parse errors from partial writes */ }
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

/** Hot-update the live injection config. Called after auto-ban. */
export function updateLiveInjectionConfig(patch: Partial<InjectionConfig>): void {
  liveInjectionConfig = { ...liveInjectionConfig, ...patch };
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
