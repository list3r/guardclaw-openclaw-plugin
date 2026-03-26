// src/config-schema.ts
import { Type } from "@sinclair/typebox";
var guardClawConfigSchema = Type.Object({
  injection: Type.Optional(
    Type.Object({
      enabled: Type.Optional(Type.Boolean()),
      heuristics_only: Type.Optional(Type.Boolean()),
      block_threshold: Type.Optional(Type.Number()),
      sanitise_threshold: Type.Optional(Type.Number()),
      alert_channel: Type.Optional(Type.String()),
      exempt_sources: Type.Optional(Type.Array(Type.String())),
      exempt_senders: Type.Optional(Type.Array(Type.String())),
      banned_senders: Type.Optional(Type.Array(Type.String()))
    })
  ),
  privacy: Type.Optional(
    Type.Object({
      enabled: Type.Optional(Type.Boolean()),
      s2Policy: Type.Optional(
        Type.Union([Type.Literal("proxy"), Type.Literal("local")])
      ),
      proxyPort: Type.Optional(Type.Number()),
      checkpoints: Type.Optional(
        Type.Object({
          onUserMessage: Type.Optional(
            Type.Array(
              Type.Union([Type.Literal("ruleDetector"), Type.Literal("localModelDetector")])
            )
          ),
          onToolCallProposed: Type.Optional(
            Type.Array(
              Type.Union([Type.Literal("ruleDetector"), Type.Literal("localModelDetector")])
            )
          ),
          onToolCallExecuted: Type.Optional(
            Type.Array(
              Type.Union([Type.Literal("ruleDetector"), Type.Literal("localModelDetector")])
            )
          )
        })
      ),
      rules: Type.Optional(
        Type.Object({
          keywords: Type.Optional(
            Type.Object({
              S2: Type.Optional(Type.Array(Type.String())),
              S3: Type.Optional(Type.Array(Type.String()))
            })
          ),
          patterns: Type.Optional(
            Type.Object({
              S2: Type.Optional(Type.Array(Type.String())),
              S3: Type.Optional(Type.Array(Type.String()))
            })
          ),
          tools: Type.Optional(
            Type.Object({
              S2: Type.Optional(
                Type.Object({
                  tools: Type.Optional(Type.Array(Type.String())),
                  paths: Type.Optional(Type.Array(Type.String()))
                })
              ),
              S3: Type.Optional(
                Type.Object({
                  tools: Type.Optional(Type.Array(Type.String())),
                  paths: Type.Optional(Type.Array(Type.String()))
                })
              )
            })
          )
        })
      ),
      localModel: Type.Optional(
        Type.Object({
          enabled: Type.Optional(Type.Boolean()),
          type: Type.Optional(
            Type.Union([
              Type.Literal("openai-compatible"),
              Type.Literal("ollama-native"),
              Type.Literal("custom")
            ])
          ),
          provider: Type.Optional(Type.String()),
          model: Type.Optional(Type.String()),
          endpoint: Type.Optional(Type.String()),
          apiKey: Type.Optional(Type.String()),
          module: Type.Optional(Type.String())
        })
      ),
      guardAgent: Type.Optional(
        Type.Object({
          id: Type.Optional(Type.String()),
          workspace: Type.Optional(Type.String()),
          model: Type.Optional(Type.String())
        })
      ),
      localProviders: Type.Optional(Type.Array(Type.String())),
      toolAllowlist: Type.Optional(Type.Array(Type.String())),
      modelPricing: Type.Optional(
        Type.Record(
          Type.String(),
          Type.Object({
            inputPer1M: Type.Optional(Type.Number()),
            outputPer1M: Type.Optional(Type.Number())
          })
        )
      ),
      session: Type.Optional(
        Type.Object({
          isolateGuardHistory: Type.Optional(Type.Boolean()),
          baseDir: Type.Optional(Type.String()),
          injectDualHistory: Type.Optional(Type.Boolean()),
          historyLimit: Type.Optional(Type.Number())
        })
      ),
      routers: Type.Optional(
        Type.Record(
          Type.String(),
          Type.Object({
            enabled: Type.Optional(Type.Boolean()),
            type: Type.Optional(Type.Union([Type.Literal("builtin"), Type.Literal("custom"), Type.Literal("configurable")])),
            module: Type.Optional(Type.String()),
            weight: Type.Optional(Type.Number()),
            options: Type.Optional(Type.Record(Type.String(), Type.Unknown()))
          })
        )
      ),
      pipeline: Type.Optional(
        Type.Object({
          onUserMessage: Type.Optional(Type.Array(Type.String())),
          onToolCallProposed: Type.Optional(Type.Array(Type.String())),
          onToolCallExecuted: Type.Optional(Type.Array(Type.String()))
        })
      ),
      redaction: Type.Optional(
        Type.Object({
          internalIp: Type.Optional(Type.Boolean()),
          email: Type.Optional(Type.Boolean()),
          envVar: Type.Optional(Type.Boolean()),
          creditCard: Type.Optional(Type.Boolean()),
          chinesePhone: Type.Optional(Type.Boolean()),
          chineseId: Type.Optional(Type.Boolean()),
          chineseAddress: Type.Optional(Type.Boolean()),
          pin: Type.Optional(Type.Boolean())
        })
      )
    })
  )
});
var defaultPrivacyConfig = {
  enabled: true,
  s2Policy: "proxy",
  proxyPort: 8403,
  checkpoints: {
    onUserMessage: ["ruleDetector", "localModelDetector"],
    onToolCallProposed: ["ruleDetector"],
    onToolCallExecuted: ["ruleDetector"]
  },
  rules: {
    keywords: {
      S2: [],
      S3: []
    },
    patterns: {
      S2: [],
      S3: []
    },
    tools: {
      S2: { tools: [], paths: [] },
      S3: { tools: [], paths: [] }
    }
  },
  localModel: {
    enabled: true,
    type: "openai-compatible",
    model: "openbmb/minicpm4.1",
    endpoint: "http://localhost:11434"
  },
  guardAgent: {
    id: "guard",
    workspace: "~/.openclaw/workspace-guard",
    model: "ollama/openbmb/minicpm4.1"
  },
  localProviders: [],
  toolAllowlist: [],
  modelPricing: {
    "claude-sonnet-4.6": { inputPer1M: 3, outputPer1M: 15 },
    "claude-3.5-sonnet": { inputPer1M: 3, outputPer1M: 15 },
    "claude-3.5-haiku": { inputPer1M: 0.8, outputPer1M: 4 },
    "gpt-4o": { inputPer1M: 2.5, outputPer1M: 10 },
    "gpt-4o-mini": { inputPer1M: 0.15, outputPer1M: 0.6 },
    "o4-mini": { inputPer1M: 1.1, outputPer1M: 4.4 },
    "gemini-2.0-flash": { inputPer1M: 0.1, outputPer1M: 0.4 },
    "deepseek-chat": { inputPer1M: 0.27, outputPer1M: 1.1 }
  },
  redaction: {
    internalIp: false,
    email: false,
    envVar: false,
    creditCard: false,
    chinesePhone: false,
    chineseId: false,
    chineseAddress: false,
    pin: false
  },
  session: {
    isolateGuardHistory: true,
    baseDir: "~/.openclaw",
    injectDualHistory: true,
    historyLimit: 20
  },
  routers: {
    privacy: { enabled: true, type: "builtin" }
  },
  pipeline: {
    onUserMessage: ["privacy"],
    onToolCallProposed: ["privacy"],
    onToolCallExecuted: ["privacy"]
  }
};
var defaultInjectionConfig = {
  enabled: true,
  heuristics_only: false,
  block_threshold: 70,
  sanitise_threshold: 30,
  alert_channel: "1483608914774986943",
  exempt_sources: [],
  exempt_senders: ["1317396442993922061"],
  banned_senders: []
};

// src/live-config.ts
import { readFileSync, watch } from "fs";
var liveConfig = { ...defaultPrivacyConfig };
var liveInjectionConfig = { ...defaultInjectionConfig };
var configWatcher = null;
var injectionAttemptCounts = /* @__PURE__ */ new Map();
function initLiveConfig(pluginConfig) {
  const userConfig = pluginConfig?.privacy ?? {};
  liveConfig = mergeConfig(userConfig);
  const userInjection = pluginConfig?.privacy?.injection ?? {};
  liveInjectionConfig = { ...defaultInjectionConfig, ...userInjection };
}
function watchConfigFile(configPath, logger) {
  if (configWatcher) return;
  let debounce = null;
  try {
    configWatcher = watch(configPath, () => {
      if (debounce) clearTimeout(debounce);
      debounce = setTimeout(() => {
        try {
          const raw = JSON.parse(readFileSync(configPath, "utf-8"));
          const privacy = raw.privacy ?? {};
          liveConfig = mergeConfig(privacy);
          const injection = raw.privacy?.injection ?? {};
          liveInjectionConfig = { ...defaultInjectionConfig, ...injection };
          logger.info("[GuardClaw] guardclaw.json changed \u2014 config hot-reloaded");
        } catch {
        }
      }, 300);
    });
  } catch {
  }
}
function getLiveConfig() {
  return liveConfig;
}
function getLiveInjectionConfig() {
  return liveInjectionConfig;
}
function updateLiveConfig(patch) {
  liveConfig = mergeConfig({ ...liveConfig, ...patch });
}
function updateLiveInjectionConfig(patch) {
  liveInjectionConfig = { ...liveInjectionConfig, ...patch };
}
function mergeConfig(userConfig) {
  return {
    ...defaultPrivacyConfig,
    ...userConfig,
    checkpoints: { ...defaultPrivacyConfig.checkpoints, ...userConfig.checkpoints },
    rules: {
      keywords: { ...defaultPrivacyConfig.rules?.keywords, ...userConfig.rules?.keywords },
      patterns: { ...defaultPrivacyConfig.rules?.patterns, ...userConfig.rules?.patterns },
      tools: {
        S2: { ...defaultPrivacyConfig.rules?.tools?.S2, ...userConfig.rules?.tools?.S2 },
        S3: { ...defaultPrivacyConfig.rules?.tools?.S3, ...userConfig.rules?.tools?.S3 }
      }
    },
    localModel: { ...defaultPrivacyConfig.localModel, ...userConfig.localModel },
    guardAgent: { ...defaultPrivacyConfig.guardAgent, ...userConfig.guardAgent },
    session: { ...defaultPrivacyConfig.session, ...userConfig.session },
    localProviders: [
      ...defaultPrivacyConfig.localProviders,
      ...userConfig.localProviders ?? []
    ],
    modelPricing: {
      ...defaultPrivacyConfig.modelPricing,
      ...userConfig.modelPricing
    },
    redaction: { ...defaultPrivacyConfig.redaction, ...userConfig.redaction }
  };
}

// src/token-stats.ts
import { readFile, writeFile, mkdir } from "fs/promises";
import { dirname } from "path";

// src/loop-detection-level.ts
var sessionStates = /* @__PURE__ */ new Map();
function levelMax(a, b) {
  const rank = { S1: 1, S2: 2, S3: 3 };
  return rank[a] >= rank[b] ? a : b;
}
function resolveSessionKey(sessionKey) {
  return sessionKey?.trim() || "__global__";
}
function getOrCreateSessionState(sessionKey) {
  const key = resolveSessionKey(sessionKey);
  const existing = sessionStates.get(key);
  if (existing) return existing;
  const next = {
    sessionKey: key,
    currentLoop: null,
    lastCompletedLoop: null,
    lastActivityAt: Date.now()
  };
  sessionStates.set(key, next);
  return next;
}
function pickSessionKey(preferred) {
  if (preferred?.trim()) return preferred.trim();
  let best = null;
  for (const state of sessionStates.values()) {
    if (!best || state.lastActivityAt > best.lastActivityAt) {
      best = state;
    }
  }
  return best?.sessionKey ?? "__global__";
}
function recordLoopDetection(sessionKey, level) {
  const state = getOrCreateSessionState(sessionKey);
  const now = Date.now();
  if (!state.currentLoop) {
    state.currentLoop = {
      startedAt: now,
      lastUpdatedAt: now,
      highestLevel: level,
      eventCount: 1
    };
  } else {
    state.currentLoop.highestLevel = levelMax(state.currentLoop.highestLevel, level);
    state.currentLoop.lastUpdatedAt = now;
    state.currentLoop.eventCount += 1;
  }
  state.lastActivityAt = now;
}
function finalizeLoop(sessionKey, timestamp) {
  const state = getOrCreateSessionState(sessionKey);
  const now = timestamp ?? Date.now();
  if (state.currentLoop) {
    state.lastCompletedLoop = {
      ...state.currentLoop,
      lastUpdatedAt: now
    };
    state.currentLoop = null;
    state.lastActivityAt = now;
    return;
  }
  state.lastActivityAt = now;
}
function getCurrentLoopHighestLevel(sessionKey) {
  const key = pickSessionKey(sessionKey);
  const state = sessionStates.get(key);
  if (!state) {
    return {
      sessionKey: key,
      loopState: "idle",
      highestLevel: "S1",
      startedAt: null,
      lastUpdatedAt: null,
      eventCount: 0
    };
  }
  if (state.currentLoop) {
    return {
      sessionKey: state.sessionKey,
      loopState: "in_progress",
      highestLevel: state.currentLoop.highestLevel,
      startedAt: state.currentLoop.startedAt,
      lastUpdatedAt: state.currentLoop.lastUpdatedAt,
      eventCount: state.currentLoop.eventCount
    };
  }
  if (state.lastCompletedLoop) {
    return {
      sessionKey: state.sessionKey,
      loopState: "completed",
      highestLevel: state.lastCompletedLoop.highestLevel,
      startedAt: state.lastCompletedLoop.startedAt,
      lastUpdatedAt: state.lastCompletedLoop.lastUpdatedAt,
      eventCount: state.lastCompletedLoop.eventCount
    };
  }
  return {
    sessionKey: state.sessionKey,
    loopState: "idle",
    highestLevel: "S1",
    startedAt: null,
    lastUpdatedAt: null,
    eventCount: 0
  };
}

// src/session-state.ts
var sessionStates2 = /* @__PURE__ */ new Map();
var pendingDetections = /* @__PURE__ */ new Map();
var activeLocalRouting = /* @__PURE__ */ new Set();
function markSessionAsPrivate(sessionKey, level) {
  const existing = sessionStates2.get(sessionKey);
  if (existing) {
    existing.currentTurnLevel = getHigherLevel(existing.currentTurnLevel, level);
    existing.highestLevel = getHigherLevel(existing.highestLevel, level);
    existing.isPrivate = existing.currentTurnLevel !== "S1";
  } else {
    const isPrivate = level === "S2" || level === "S3";
    sessionStates2.set(sessionKey, {
      sessionKey,
      isPrivate,
      highestLevel: level,
      currentTurnLevel: level,
      detectionHistory: []
    });
  }
}
function isSessionMarkedPrivate(sessionKey) {
  const state = sessionStates2.get(sessionKey);
  if (!state) return false;
  return state.currentTurnLevel !== "S1";
}
function resetTurnLevel(sessionKey) {
  const existing = sessionStates2.get(sessionKey);
  if (existing) {
    existing.currentTurnLevel = "S1";
    existing.isPrivate = false;
  }
}
function getSessionHighestLevel(sessionKey) {
  return sessionStates2.get(sessionKey)?.highestLevel ?? "S1";
}
function recordDetection(sessionKey, level, checkpoint, reason) {
  let state = sessionStates2.get(sessionKey);
  if (!state) {
    state = {
      sessionKey,
      isPrivate: false,
      highestLevel: "S1",
      currentTurnLevel: "S1",
      detectionHistory: []
    };
    sessionStates2.set(sessionKey, state);
  }
  state.detectionHistory.push({
    timestamp: Date.now(),
    level,
    checkpoint,
    reason
  });
  if (state.detectionHistory.length > 50) {
    state.detectionHistory = state.detectionHistory.slice(-50);
  }
  recordLoopDetection(sessionKey, level);
}
function clearSessionState(sessionKey) {
  sessionStates2.delete(sessionKey);
  activeLocalRouting.delete(sessionKey);
  pendingDetections.delete(sessionKey);
}
function getAllSessionStates() {
  return new Map(sessionStates2);
}
function stashDetection(sessionKey, detection) {
  pendingDetections.set(sessionKey, detection);
}
function getPendingDetection(sessionKey) {
  return pendingDetections.get(sessionKey);
}
function consumeDetection(sessionKey) {
  const d = pendingDetections.get(sessionKey);
  pendingDetections.delete(sessionKey);
  return d;
}
function trackSessionLevel(sessionKey, level) {
  const existing = sessionStates2.get(sessionKey);
  if (existing) {
    existing.highestLevel = getHigherLevel(existing.highestLevel, level);
    existing.currentTurnLevel = getHigherLevel(existing.currentTurnLevel, level);
  } else {
    sessionStates2.set(sessionKey, {
      sessionKey,
      isPrivate: false,
      highestLevel: level,
      currentTurnLevel: level,
      detectionHistory: []
    });
  }
}
function setActiveLocalRouting(sessionKey) {
  activeLocalRouting.add(sessionKey);
}
function clearActiveLocalRouting(sessionKey) {
  activeLocalRouting.delete(sessionKey);
}
function isActiveLocalRouting(sessionKey) {
  return activeLocalRouting.has(sessionKey);
}
var pendingSenderIds = /* @__PURE__ */ new Map();
function setLastSenderId(channelId, senderId) {
  if (channelId && senderId) pendingSenderIds.set(channelId, senderId);
}
function getLastSenderId(channelId) {
  return pendingSenderIds.get(channelId);
}
function clearLastSenderId(channelId) {
  pendingSenderIds.delete(channelId);
}
function getHigherLevel(a, b) {
  const order = { S1: 1, S2: 2, S3: 3 };
  return order[a] >= order[b] ? a : b;
}

// src/token-stats.ts
var MAX_HOURLY_BUCKETS = 72;
var MAX_SESSIONS = 200;
function emptyBucket() {
  return { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, totalTokens: 0, requestCount: 0, estimatedCost: 0 };
}
function emptySourceBuckets() {
  return { router: emptyBucket(), task: emptyBucket() };
}
function currentHourKey() {
  return (/* @__PURE__ */ new Date()).toISOString().slice(0, 13);
}
function emptyStats() {
  return {
    lifetime: { cloud: emptyBucket(), local: emptyBucket(), proxy: emptyBucket() },
    bySource: emptySourceBuckets(),
    hourly: [],
    sessions: {},
    startedAt: Date.now(),
    lastUpdatedAt: Date.now()
  };
}
function addToBucket(bucket, usage, cost = 0) {
  const input = usage?.input ?? 0;
  const output = usage?.output ?? 0;
  const cacheRead = usage?.cacheRead ?? 0;
  bucket.inputTokens += input;
  bucket.outputTokens += output;
  bucket.cacheReadTokens += cacheRead;
  bucket.totalTokens += usage?.total ?? input + output;
  bucket.requestCount += 1;
  bucket.estimatedCost += cost;
}
function lookupPricing(model) {
  const pricing = getLiveConfig().modelPricing;
  if (!pricing) return { inputPer1M: 3, outputPer1M: 15 };
  if (pricing[model]) {
    return { inputPer1M: pricing[model].inputPer1M ?? 3, outputPer1M: pricing[model].outputPer1M ?? 15 };
  }
  const lowerModel = model.toLowerCase();
  for (const [key, val] of Object.entries(pricing)) {
    if (lowerModel.includes(key.toLowerCase())) {
      return { inputPer1M: val.inputPer1M ?? 3, outputPer1M: val.outputPer1M ?? 15 };
    }
  }
  return { inputPer1M: 3, outputPer1M: 15 };
}
function calculateCost(model, usage) {
  const input = usage?.input ?? 0;
  const output = usage?.output ?? 0;
  const p = lookupPricing(model);
  return (input * p.inputPer1M + output * p.outputPer1M) / 1e6;
}
function classifyBySession(sessionKey) {
  const level = getSessionHighestLevel(sessionKey);
  if (level === "S3") return "local";
  if (level === "S2") {
    const policy = getLiveConfig().s2Policy;
    return policy === "local" ? "local" : "proxy";
  }
  return "cloud";
}
var TokenStatsCollector = class {
  data;
  filePath;
  flushTimer = null;
  dirty = false;
  constructor(filePath) {
    this.filePath = filePath;
    this.data = emptyStats();
  }
  /** Load persisted stats from disk. Merges with empty defaults for missing fields. */
  async load() {
    try {
      const raw = await readFile(this.filePath, "utf-8");
      const parsed = JSON.parse(raw);
      const rawSessions = parsed.sessions && typeof parsed.sessions === "object" ? parsed.sessions : {};
      const parsedBySource = parsed.bySource;
      this.data = {
        lifetime: {
          cloud: { ...emptyBucket(), ...parsed.lifetime?.cloud },
          local: { ...emptyBucket(), ...parsed.lifetime?.local },
          proxy: { ...emptyBucket(), ...parsed.lifetime?.proxy }
        },
        bySource: {
          router: { ...emptyBucket(), ...parsedBySource?.router },
          task: { ...emptyBucket(), ...parsedBySource?.task }
        },
        hourly: Array.isArray(parsed.hourly) ? parsed.hourly : [],
        sessions: rawSessions,
        startedAt: parsed.startedAt ?? Date.now(),
        lastUpdatedAt: parsed.lastUpdatedAt ?? Date.now()
      };
    } catch {
      this.data = emptyStats();
    }
  }
  /** Start periodic flush (every 5 minutes). */
  startAutoFlush() {
    if (this.flushTimer) return;
    this.flushTimer = setInterval(() => {
      if (this.dirty) this.flush().catch(() => {
      });
    }, 3e5);
    if (this.flushTimer && typeof this.flushTimer === "object" && "unref" in this.flushTimer) {
      this.flushTimer.unref();
    }
  }
  /** Stop periodic flush. */
  stopAutoFlush() {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }
  /** Record a usage event from llm_output hook or router overhead. */
  record(event) {
    const category = classifyBySession(event.sessionKey);
    const source = event.source ?? "task";
    const now = Date.now();
    const cost = category !== "local" ? calculateCost(event.model, event.usage) : 0;
    addToBucket(this.data.lifetime[category], event.usage, cost);
    addToBucket(this.data.bySource[source], event.usage, cost);
    const hourKey = currentHourKey();
    let hourly = this.data.hourly.find((h) => h.hour === hourKey);
    if (!hourly) {
      hourly = { hour: hourKey, cloud: emptyBucket(), local: emptyBucket(), proxy: emptyBucket(), bySource: emptySourceBuckets() };
      this.data.hourly.push(hourly);
      if (this.data.hourly.length > MAX_HOURLY_BUCKETS) {
        this.data.hourly = this.data.hourly.slice(-MAX_HOURLY_BUCKETS);
      }
    }
    if (!hourly.bySource) hourly.bySource = emptySourceBuckets();
    addToBucket(hourly[category], event.usage, cost);
    addToBucket(hourly.bySource[source], event.usage, cost);
    const sk = event.sessionKey;
    if (sk) {
      let sess = this.data.sessions[sk];
      if (!sess) {
        sess = {
          sessionKey: sk,
          highestLevel: getSessionHighestLevel(sk),
          cloud: emptyBucket(),
          local: emptyBucket(),
          proxy: emptyBucket(),
          bySource: emptySourceBuckets(),
          firstSeenAt: now,
          lastActiveAt: now
        };
        this.data.sessions[sk] = sess;
      }
      if (!sess.bySource) sess.bySource = emptySourceBuckets();
      sess.highestLevel = getSessionHighestLevel(sk);
      sess.lastActiveAt = now;
      addToBucket(sess[category], event.usage, cost);
      addToBucket(sess.bySource[source], event.usage, cost);
      this.evictOldSessions();
    }
    this.data.lastUpdatedAt = now;
    this.dirty = true;
  }
  evictOldSessions() {
    const keys = Object.keys(this.data.sessions);
    if (keys.length <= MAX_SESSIONS) return;
    const sorted = keys.sort(
      (a, b) => this.data.sessions[a].lastActiveAt - this.data.sessions[b].lastActiveAt
    );
    const toRemove = sorted.slice(0, keys.length - MAX_SESSIONS);
    for (const k of toRemove) delete this.data.sessions[k];
  }
  /** Get snapshot of current stats. */
  getStats() {
    return this.data;
  }
  /** Get summary for API response. */
  getSummary() {
    return {
      lifetime: this.data.lifetime,
      bySource: this.data.bySource,
      lastUpdatedAt: this.data.lastUpdatedAt,
      startedAt: this.data.startedAt
    };
  }
  /** Get hourly data for API response. */
  getHourly() {
    return this.data.hourly;
  }
  /** Get per-session stats sorted by lastActiveAt descending. */
  getSessionStats() {
    return Object.values(this.data.sessions).sort(
      (a, b) => b.lastActiveAt - a.lastActiveAt
    );
  }
  /** Reset all stats to empty and flush to disk. */
  async reset() {
    this.data = emptyStats();
    this.dirty = true;
    await this.flush();
  }
  /** Flush to disk. */
  async flush() {
    try {
      await mkdir(dirname(this.filePath), { recursive: true });
      await writeFile(this.filePath, JSON.stringify(this.data, null, 2), "utf-8");
      this.dirty = false;
    } catch {
    }
  }
};
var globalCollector = null;
function setGlobalCollector(collector) {
  globalCollector = collector;
}
function getGlobalCollector() {
  return globalCollector;
}

// src/prompt-loader.ts
import { readFileSync as readFileSync2, writeFileSync, existsSync, mkdirSync } from "fs";
import { resolve, dirname as dirname2 } from "path";
import { fileURLToPath } from "url";
var __filename = fileURLToPath(import.meta.url);
var __dirname = dirname2(__filename);
function resolvePromptsDir() {
  const candidates = [
    resolve(__dirname, "../prompts"),
    // from src/  → prompts/
    resolve(__dirname, "../../prompts")
    // from dist/src/ → prompts/
  ];
  for (const dir of candidates) {
    if (existsSync(dir)) return dir;
  }
  return candidates[0];
}
var PROMPTS_DIR = resolvePromptsDir();
var cache = /* @__PURE__ */ new Map();
function loadPrompt(name, fallback) {
  const cached = cache.get(name);
  if (cached !== void 0) return cached;
  const filePath = resolve(PROMPTS_DIR, `${name}.md`);
  let content;
  try {
    if (existsSync(filePath)) {
      content = readFileSync2(filePath, "utf-8").trim();
      console.log(`[GuardClaw] Loaded custom prompt: prompts/${name}.md`);
    } else {
      content = fallback;
    }
  } catch {
    console.warn(`[GuardClaw] Failed to read prompts/${name}.md, using default`);
    content = fallback;
  }
  cache.set(name, content);
  return content;
}
function loadPromptWithVars(name, fallback, vars) {
  let prompt = loadPrompt(name, fallback);
  for (const [key, value] of Object.entries(vars)) {
    prompt = prompt.replaceAll(`{{${key}}}`, value);
  }
  return prompt;
}
function invalidatePrompt(name) {
  cache.delete(name);
}
function writePrompt(name, content) {
  mkdirSync(PROMPTS_DIR, { recursive: true });
  const filePath = resolve(PROMPTS_DIR, `${name}.md`);
  writeFileSync(filePath, content, "utf-8");
  invalidatePrompt(name);
}
function readPromptFromDisk(name) {
  const filePath = resolve(PROMPTS_DIR, `${name}.md`);
  try {
    if (existsSync(filePath)) {
      return readFileSync2(filePath, "utf-8").trim();
    }
  } catch {
  }
  return null;
}

// src/correction-store.ts
import { readFileSync as readFileSync3, writeFileSync as writeFileSync2, mkdirSync as mkdirSync2, existsSync as existsSync2 } from "fs";
import { join, dirname as dirname3 } from "path";
var DEFAULT_FILE_PATH = join(
  process.env.HOME ?? "/tmp",
  ".openclaw",
  "guardclaw-corrections.json"
);
var DEFAULT_EMBEDDING_ENDPOINT = "http://localhost:1234";
var DEFAULT_EMBEDDING_MODEL = "text-embedding-nomic-embed-text-v1.5";
var DEFAULT_MAX_CORRECTIONS = 200;
var DEFAULT_TOP_K = 3;
var EMBEDDING_TIMEOUT_MS = 1e4;
var corrections = [];
var storeConfig = {};
var loaded = false;
function resolveFilePath() {
  return storeConfig.filePath ?? DEFAULT_FILE_PATH;
}
function loadCorrections(config) {
  if (config) storeConfig = config;
  const filePath = resolveFilePath();
  try {
    if (existsSync2(filePath)) {
      const raw = JSON.parse(readFileSync3(filePath, "utf-8"));
      corrections = Array.isArray(raw.corrections) ? raw.corrections : [];
    }
  } catch {
    console.warn("[GuardClaw] Failed to load corrections, starting fresh");
    corrections = [];
  }
  loaded = true;
  return corrections;
}
function saveCorrections() {
  const filePath = resolveFilePath();
  try {
    mkdirSync2(dirname3(filePath), { recursive: true });
    writeFileSync2(
      filePath,
      JSON.stringify({ corrections, updatedAt: (/* @__PURE__ */ new Date()).toISOString() }, null, 2),
      "utf-8"
    );
  } catch (err) {
    console.error("[GuardClaw] Failed to save corrections:", err);
  }
}
function getCorrections() {
  if (!loaded) loadCorrections();
  return corrections;
}
async function addCorrection(input) {
  if (!loaded) loadCorrections();
  const correction = {
    ...input,
    id: generateId(),
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  };
  try {
    correction.embedding = await embedText(input.message);
  } catch (err) {
    console.warn("[GuardClaw] Could not compute correction embedding:", err);
  }
  corrections.push(correction);
  const max = storeConfig.maxCorrections ?? DEFAULT_MAX_CORRECTIONS;
  if (corrections.length > max) {
    corrections = corrections.slice(-max);
  }
  saveCorrections();
  console.log(
    `[GuardClaw] Correction added: ${correction.predicted} \u2192 ${correction.corrected} (${correction.id})`
  );
  return correction;
}
function deleteCorrection(id) {
  if (!loaded) loadCorrections();
  const before = corrections.length;
  corrections = corrections.filter((c) => c.id !== id);
  if (corrections.length < before) {
    saveCorrections();
    return true;
  }
  return false;
}
async function findSimilarCorrections(message, topK) {
  if (!loaded) loadCorrections();
  const k = topK ?? storeConfig.topK ?? DEFAULT_TOP_K;
  const withEmbeddings = corrections.filter((c) => c.embedding && c.embedding.length > 0);
  if (withEmbeddings.length === 0) return [];
  let queryEmbedding;
  try {
    queryEmbedding = await embedText(message);
  } catch {
    return [];
  }
  const scored = withEmbeddings.map((c) => ({
    ...c,
    similarity: cosineSimilarity(queryEmbedding, c.embedding)
  })).filter((c) => c.similarity > 0.3).sort((a, b) => b.similarity - a.similarity).slice(0, k);
  return scored;
}
async function buildFewShotExamples(message) {
  const similar = await findSimilarCorrections(message);
  if (similar.length === 0) return "";
  const examples = similar.map(
    (c) => `[EXAMPLE]
Message: ${c.message.slice(0, 300)}
Correct: {"level":"${c.corrected}","reason":"${c.reason ?? "corrected from " + c.predicted}"}
[/EXAMPLE]`
  );
  return "The following are corrected examples for similar messages:\n" + examples.join("\n") + "\n\nNow classify the following:\n";
}
var AUTHORITATIVE_THRESHOLD = 0.7;
async function getAuthoritativeOverride(message) {
  const similar = await findSimilarCorrections(message, 1);
  if (similar.length === 0) return null;
  const best = similar[0];
  if (best.similarity < AUTHORITATIVE_THRESHOLD) return null;
  return {
    level: best.corrected,
    reason: `Correction override (${(best.similarity * 100).toFixed(0)}% match): ${best.reason ?? "corrected from " + best.predicted}`,
    correctionId: best.id,
    similarity: best.similarity
  };
}
async function embedText(text) {
  const endpoint = storeConfig.embeddingEndpoint ?? DEFAULT_EMBEDDING_ENDPOINT;
  const model = storeConfig.embeddingModel ?? DEFAULT_EMBEDDING_MODEL;
  const url = `${endpoint}/v1/embeddings`;
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      input: text.slice(0, 2e3)
      // nomic-embed-text handles up to 8K tokens but truncate for speed
    }),
    signal: AbortSignal.timeout(EMBEDDING_TIMEOUT_MS)
  });
  if (!response.ok) {
    throw new Error(`Embedding API error: ${response.status} ${response.statusText}`);
  }
  const data = await response.json();
  const embedding = data.data?.[0]?.embedding;
  if (!embedding || embedding.length === 0) {
    throw new Error("Embedding response missing vector data");
  }
  return embedding;
}
function cosineSimilarity(a, b) {
  if (a.length !== b.length || a.length === 0) return 0;
  let dotProduct = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denominator = Math.sqrt(normA) * Math.sqrt(normB);
  return denominator === 0 ? 0 : dotProduct / denominator;
}
function generateId() {
  return `corr_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

// src/types.ts
function levelToNumeric(level) {
  switch (level) {
    case "S1":
      return 1;
    case "S2":
      return 2;
    case "S3":
      return 3;
  }
}
function numericToLevel(numeric) {
  switch (numeric) {
    case 1:
      return "S1";
    case 2:
      return "S2";
    case 3:
      return "S3";
    default:
      return "S1";
  }
}
function maxLevel(...levels) {
  if (levels.length === 0) return "S1";
  const numeric = levels.map(levelToNumeric);
  const max = Math.max(...numeric);
  return numericToLevel(max);
}

// src/usage-intel.ts
var BUILTIN_LOCAL_PROVIDERS = /* @__PURE__ */ new Set([
  "ollama",
  "llama.cpp",
  "localai",
  "llamafile",
  "lmstudio",
  "vllm",
  "mlx",
  "sglang",
  "tgi",
  "koboldcpp",
  "tabbyapi",
  "nitro"
]);
var sessionLoopStates = /* @__PURE__ */ new Map();
function emptyCounter() {
  return { input: 0, output: 0, total: 0 };
}
function emptyRouterSummary() {
  return {
    detection: emptyCounter(),
    desensitization: emptyCounter(),
    combined: emptyCounter()
  };
}
function usageToCounter(usage) {
  const input = usage?.input ?? 0;
  const output = usage?.output ?? 0;
  return {
    input,
    output,
    total: usage?.total ?? input + output
  };
}
function addCounter(target, value) {
  target.input += value.input;
  target.output += value.output;
  target.total += value.total;
}
function resolveSessionKey2(sessionKey) {
  return sessionKey?.trim() || "__global__";
}
function getOrCreateSessionState2(sessionKey) {
  const key = resolveSessionKey2(sessionKey);
  const existing = sessionLoopStates.get(key);
  if (existing) return existing;
  const next = {
    sessionKey: key,
    currentLoop: null,
    lastCompletedLoop: null,
    lastActivityAt: Date.now()
  };
  sessionLoopStates.set(key, next);
  return next;
}
function ensureCurrentLoop(state) {
  if (!state.currentLoop) {
    state.currentLoop = {
      startedAt: Date.now(),
      routerTokens: emptyRouterSummary(),
      routerLocalTokens: emptyCounter(),
      routerCloudTokens: emptyCounter()
    };
  }
  return state.currentLoop;
}
function resolveOriginByProvider(provider, extraLocalProviders, originHint) {
  if (originHint) {
    return { origin: originHint, reason: "origin_hint" };
  }
  const lower = provider.toLowerCase();
  if (lower === "guardclaw-privacy") {
    return { origin: "cloud", reason: "guardclaw_proxy_to_cloud" };
  }
  if (BUILTIN_LOCAL_PROVIDERS.has(lower)) {
    return { origin: "local", reason: "builtin_local_provider" };
  }
  if (extraLocalProviders?.some((p) => p.toLowerCase() === lower)) {
    return { origin: "local", reason: "configured_local_provider" };
  }
  return { origin: "cloud", reason: "provider_not_local" };
}
function pickLatestSessionKey(preferred) {
  if (preferred?.trim()) return preferred.trim();
  let latest = null;
  for (const state of sessionLoopStates.values()) {
    if (!state.lastCompletedLoop) continue;
    if (!latest || state.lastActivityAt > latest.lastActivityAt) {
      latest = state;
    }
  }
  return latest?.sessionKey ?? null;
}
function recordRouterOperation(sessionKey, phase, usage, _model, provider) {
  const state = getOrCreateSessionState2(sessionKey);
  const loop = ensureCurrentLoop(state);
  const counter = usageToCounter(usage);
  addCounter(loop.routerTokens[phase], counter);
  addCounter(loop.routerTokens.combined, counter);
  const origin = resolveOriginByProvider(provider ?? "ollama").origin;
  if (origin === "local") {
    addCounter(loop.routerLocalTokens, counter);
  } else {
    addCounter(loop.routerCloudTokens, counter);
  }
  state.lastActivityAt = Date.now();
}
function recordFinalReply(params) {
  const state = getOrCreateSessionState2(params.sessionKey);
  const loop = ensureCurrentLoop(state);
  const resolved = resolveOriginByProvider(
    params.provider,
    params.extraLocalProviders,
    params.originHint
  );
  const taskCounter = usageToCounter(params.usage);
  const loopLocalTokens = {
    ...loop.routerLocalTokens
  };
  const loopCloudTokens = {
    ...loop.routerCloudTokens
  };
  if (resolved.origin === "local") {
    addCounter(loopLocalTokens, taskCounter);
  } else {
    addCounter(loopCloudTokens, taskCounter);
  }
  const loopTotalTokens = {
    input: loopLocalTokens.input + loopCloudTokens.input,
    output: loopLocalTokens.output + loopCloudTokens.output,
    total: loopLocalTokens.total + loopCloudTokens.total
  };
  state.lastCompletedLoop = {
    sessionKey: state.sessionKey,
    turnTs: Date.now(),
    startedAt: loop.startedAt,
    provider: params.provider,
    model: params.model,
    origin: resolved.origin,
    reason: params.reasonHint ?? resolved.reason,
    routerTokens: {
      detection: { ...loop.routerTokens.detection },
      desensitization: { ...loop.routerTokens.desensitization },
      combined: { ...loop.routerTokens.combined }
    },
    loopTotalTokens,
    loopLocalTokens,
    loopCloudTokens
  };
  state.currentLoop = null;
  state.lastActivityAt = Date.now();
}
function getLastTurnTokens(sessionKey) {
  const key = pickLatestSessionKey(sessionKey);
  if (!key) return null;
  const snap = sessionLoopStates.get(key)?.lastCompletedLoop;
  if (!snap) return null;
  return {
    sessionKey: snap.sessionKey,
    turnTs: snap.turnTs,
    detection: { ...snap.routerTokens.detection },
    desensitization: { ...snap.routerTokens.desensitization },
    combined: { ...snap.routerTokens.combined }
  };
}
function getLastReplyModelOrigin(sessionKey) {
  const key = pickLatestSessionKey(sessionKey);
  if (!key) return null;
  const snap = sessionLoopStates.get(key)?.lastCompletedLoop;
  if (!snap) return null;
  return {
    sessionKey: snap.sessionKey,
    timestamp: snap.turnTs,
    provider: snap.provider,
    model: snap.model,
    origin: snap.origin,
    reason: snap.reason
  };
}
function getLastReplyLoopSummary(sessionKey) {
  const key = pickLatestSessionKey(sessionKey);
  if (!key) return null;
  const snap = sessionLoopStates.get(key)?.lastCompletedLoop;
  if (!snap) return null;
  return {
    ...snap,
    routerTokens: {
      detection: { ...snap.routerTokens.detection },
      desensitization: { ...snap.routerTokens.desensitization },
      combined: { ...snap.routerTokens.combined }
    },
    loopTotalTokens: { ...snap.loopTotalTokens },
    loopLocalTokens: { ...snap.loopLocalTokens },
    loopCloudTokens: { ...snap.loopCloudTokens }
  };
}

// src/local-model.ts
var _customProviderCache = /* @__PURE__ */ new Map();
async function loadCustomProvider(modulePath) {
  const cached = _customProviderCache.get(modulePath);
  if (cached) return cached;
  const mod = await import(modulePath);
  if (typeof mod.callChat !== "function") {
    throw new Error(`Custom edge provider at "${modulePath}" must export a callChat() function`);
  }
  _customProviderCache.set(modulePath, mod);
  return mod;
}
async function callChatCompletion(endpoint, model, messages, options) {
  const providerType = options?.providerType ?? "openai-compatible";
  let result;
  switch (providerType) {
    case "ollama-native":
      result = await callOllamaNative(endpoint, model, messages, options);
      break;
    case "custom": {
      if (!options?.customModule) {
        throw new Error("Custom edge provider requires a 'module' path in localModel config");
      }
      const provider = await loadCustomProvider(options.customModule);
      const text = await provider.callChat(endpoint, model, messages, options);
      result = { text };
      break;
    }
    case "openai-compatible":
    default:
      result = await callOpenAICompatible(endpoint, model, messages, options);
      break;
  }
  return result;
}
var GUARDCLAW_FETCH_TIMEOUT_MS = 6e4;
async function callOpenAICompatible(endpoint, model, messages, options) {
  const url = `${endpoint}/v1/chat/completions`;
  const headers = { "Content-Type": "application/json" };
  if (options?.apiKey) {
    headers["Authorization"] = `Bearer ${options.apiKey}`;
  }
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({
      model,
      messages,
      temperature: options?.temperature ?? 0.1,
      max_tokens: options?.maxTokens ?? 800,
      stream: true,
      ...options?.stop ? { stop: options.stop } : {},
      ...options?.frequencyPenalty != null ? { frequency_penalty: options.frequencyPenalty } : {},
      ...options?.disableThinking ? { chat_template_kwargs: { enable_thinking: false } } : {}
    }),
    signal: AbortSignal.timeout(GUARDCLAW_FETCH_TIMEOUT_MS)
  });
  if (!response.ok) {
    throw new Error(`Chat completions API error: ${response.status} ${response.statusText}`);
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("text/event-stream") && response.body) {
    return await consumeSSEStream(response.body);
  }
  const data = await response.json();
  let text = data.choices?.[0]?.message?.content ?? "";
  text = stripThinkingTags(text);
  const usage = data.usage ? {
    input: data.usage.prompt_tokens ?? 0,
    output: data.usage.completion_tokens ?? 0,
    total: data.usage.total_tokens ?? (data.usage.prompt_tokens ?? 0) + (data.usage.completion_tokens ?? 0)
  } : void 0;
  return { text, usage };
}
async function consumeSSEStream(body) {
  const decoder = new TextDecoder();
  const reader = body.getReader();
  let textParts = [];
  let usage;
  let buffer = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("data:")) continue;
        const payload = trimmed.slice(5).trim();
        if (payload === "[DONE]") continue;
        try {
          const chunk = JSON.parse(payload);
          const delta = chunk.choices?.[0]?.delta;
          if (delta?.content) {
            textParts.push(delta.content);
          }
          if (chunk.usage) {
            usage = {
              input: chunk.usage.prompt_tokens ?? 0,
              output: chunk.usage.completion_tokens ?? 0,
              total: chunk.usage.total_tokens ?? 0
            };
          }
        } catch {
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
  let text = textParts.join("");
  text = stripThinkingTags(text);
  return { text, usage };
}
async function callOllamaNative(endpoint, model, messages, options) {
  const url = `${endpoint}/api/chat`;
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      messages,
      stream: false,
      options: {
        temperature: options?.temperature ?? 0.1,
        num_predict: options?.maxTokens ?? 800,
        ...options?.stop ? { stop: options.stop } : {},
        ...options?.frequencyPenalty != null ? { repeat_penalty: 1 + (options.frequencyPenalty ?? 0) } : {}
      }
    })
  });
  if (!response.ok) {
    throw new Error(`Ollama native API error: ${response.status} ${response.statusText}`);
  }
  const data = await response.json();
  let text = data.message?.content ?? "";
  text = stripThinkingTags(text);
  const promptTokens = data.prompt_eval_count ?? 0;
  const outputTokens = data.eval_count ?? 0;
  const usage = promptTokens || outputTokens ? { input: promptTokens, output: outputTokens, total: promptTokens + outputTokens } : void 0;
  return { text, usage };
}
function stripThinkingTags(text) {
  let result = text.replace(/<think>[\s\S]*?<\/think>/g, "").trim();
  const lastThinkClose = result.lastIndexOf("</think>");
  if (lastThinkClose !== -1) {
    result = result.slice(lastThinkClose + "</think>".length).trim();
  }
  return result;
}
async function detectByLocalModel(context, config) {
  if (!config.localModel?.enabled) {
    return {
      level: "S1",
      levelNumeric: 1,
      reason: "Local model detection disabled",
      detectorType: "localModelDetector",
      confidence: 0
    };
  }
  try {
    const { system, user } = await buildDetectionMessages(context);
    const result = await callLocalModel(system, user, config);
    const parsed = parseModelResponse(result.text);
    if (result.usage) {
      const collector = getGlobalCollector();
      collector?.record({
        sessionKey: context.sessionKey ?? "",
        provider: "edge",
        model: config.localModel?.model ?? "unknown",
        source: "router",
        usage: result.usage
      });
      recordRouterOperation(
        context.sessionKey,
        "detection",
        result.usage,
        config.localModel?.model ?? "unknown",
        config.localModel?.provider
      );
    }
    const messageText = context.message ?? context.toolName ?? "";
    let finalLevel = parsed.level;
    let finalReason = parsed.reason;
    let finalConfidence = parsed.confidence ?? 0.8;
    try {
      const override = await getAuthoritativeOverride(messageText);
      if (override && override.level !== parsed.level) {
        console.log(
          `[GuardClaw] Correction override: model=${parsed.level} \u2192 correction=${override.level} (${override.similarity.toFixed(2)} similarity, id=${override.correctionId})`
        );
        finalLevel = override.level;
        finalReason = override.reason;
        finalConfidence = Math.min(0.95, override.similarity);
      }
    } catch {
    }
    return {
      level: finalLevel,
      levelNumeric: levelToNumeric(finalLevel),
      reason: finalReason,
      detectorType: "localModelDetector",
      confidence: finalConfidence
    };
  } catch (err) {
    console.error("[GuardClaw] Local model detection failed:", err);
    return {
      level: "S1",
      levelNumeric: 1,
      reason: `Local model error: ${String(err)}`,
      detectorType: "localModelDetector",
      confidence: 0
    };
  }
}
var DEFAULT_DETECTION_SYSTEM_PROMPT = `[SYSTEM] You are a strict privacy classifier. Output ONLY a single JSON object \u2014 nothing else.

Classify by BOTH actual data AND intent. If the user asks to read/analyze a file, classify based on what the file WILL contain.

S3 = PRIVATE (local only, never cloud):
  - Financial: payslip, salary, tax, bank account, SSN, \u5DE5\u8D44\u5355, \u62A5\u9500\u5355, \u7A0E\u8868
  - Medical: health records, diagnoses, prescriptions, lab results, \u75C5\u5386, \u4F53\u68C0\u62A5\u544A
  - Credentials: passwords, API keys, secrets, tokens, private keys
  - ANY request to read/analyze a file about the above topics \u2192 S3
  "evaluate these passwords" \u2192 S3
  "check my payslip" \u2192 S3
  "summarize the medical record" \u2192 S3

S2 = SENSITIVE (redact PII, then send to cloud):
  - Addresses (ANY physical address, \u5730\u5740, \u4F4F\u5740, street, road, apartment, \u8DEF, \u8857, \u5C0F\u533A, \u5F04, \u53F7)
  - Gate/door codes, pickup codes, delivery tracking numbers
  - Phone numbers, email addresses, real names used as contact PII
  - License plates, SSN/ID mixed with personal context, chat logs with PII
  - File content containing the above PII \u2192 S2
  - ANY mention of "address"/"\u5730\u5740" with actual location data \u2192 S2
  "1847 Elm St, gate code 4523#" \u2192 S2
  "\u6211\u7684\u5730\u5740\u662F\u5317\u4EAC\u5E02\u671D\u9633\u533Axxx" \u2192 S2
  "\u5F20\u4F1F \u624B\u673A13912345678" \u2192 S2
  "my address is 123 Main St" \u2192 S2

S1 = SAFE: No sensitive data or intent.
  "write a poem about spring" \u2192 S1
  "how to read Excel with pandas" \u2192 S1

Rules:
- Passwords/credentials \u2192 ALWAYS S3 (never S2)
- Medical data \u2192 ALWAYS S3 (never S2)
- Gate/access/pickup codes \u2192 S2 (not S3)
- If file content is provided and contains PII \u2192 at least S2
- When unsure \u2192 pick higher level

Output format: {"level":"S1|S2|S3","reason":"brief"}`;
async function buildDetectionMessages(context) {
  const system = loadPrompt("detection-system", DEFAULT_DETECTION_SYSTEM_PROMPT);
  const contentParts = ["[CONTENT]"];
  if (context.message) {
    contentParts.push(`Message: ${context.message.slice(0, 1500)}`);
  }
  if (context.toolName) {
    contentParts.push(`Tool: ${context.toolName}`);
  }
  if (context.toolParams) {
    const paramsStr = JSON.stringify(context.toolParams, null, 2);
    contentParts.push(`Tool Parameters: ${paramsStr.slice(0, 800)}`);
  }
  if (context.toolResult) {
    const resultStr = typeof context.toolResult === "string" ? context.toolResult : JSON.stringify(context.toolResult);
    contentParts.push(`Tool Result: ${resultStr.slice(0, 800)}`);
  }
  if (context.recentContext && context.recentContext.length > 0) {
    contentParts.push(`Recent Context: ${context.recentContext.slice(-3).join(" | ")}`);
  }
  contentParts.push("[/CONTENT]");
  const messageText = context.message ?? context.toolName ?? "";
  let fewShotPrefix = "";
  try {
    fewShotPrefix = await buildFewShotExamples(messageText);
  } catch {
  }
  return { system, user: fewShotPrefix + contentParts.join("\n") };
}
async function callLocalModel(systemPrompt, userContent, config) {
  const model = config.localModel?.model ?? "openbmb/minicpm4.1";
  const endpoint = config.localModel?.endpoint ?? "http://localhost:11434";
  const providerType = config.localModel?.type ?? "openai-compatible";
  return await callChatCompletion(
    endpoint,
    model,
    [
      { role: "system", content: systemPrompt },
      { role: "user", content: userContent }
    ],
    {
      temperature: 0.1,
      maxTokens: 300,
      stop: ["\n\n", "\nExplanation", "\nNote"],
      apiKey: config.localModel?.apiKey,
      disableThinking: false,
      providerType,
      customModule: config.localModel?.module
    }
  );
}
function preRedactCredentials(content) {
  let out = content;
  out = out.replace(/\bAKIA[A-Z0-9]{16}\b/g, "[REDACTED:CREDENTIAL]");
  out = out.replace(/\bASIA[A-Z0-9]{16}\b/g, "[REDACTED:CREDENTIAL]");
  out = out.replace(/(aws_secret_access_key\s*[=:]\s*)\S+/gi, "$1[REDACTED:CREDENTIAL]");
  out = out.replace(/(AWS_SECRET_ACCESS_KEY\s*[=:]\s*)\S+/gi, "$1[REDACTED:CREDENTIAL]");
  out = out.replace(/redis:\/\/[^@\s]*:[^@\s]+@/gi, "redis://[REDACTED:CREDENTIAL]@");
  out = out.replace(/((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|amqp|smtp|ftp|ftps):\/\/[^:\s]*:)[^@\s]+(@)/gi, "$1[REDACTED:CREDENTIAL]$2");
  out = out.replace(/(pg_dump|psql)(\s+\S+)*\s+-W\s+(\S+)/gi, (m, cmd, mid, pw) => m.replace(pw, "[REDACTED:CREDENTIAL]"));
  out = out.replace(/\b(password|passwd|passphrase|pass|pwd)\s*[:=]\s*(\S+)/gi, "$1: [REDACTED:PASSWORD]");
  out = out.replace(/\b(client\s+secret|private\s+token|access\s+token|api\s+key|auth\s+token|service\s+account\s+key|signing\s+key|master\s+key|deploy\s+key|session\s+secret|webhook\s+secret|app\s+secret|shared\s+secret)\s*[:=]\s*(\S+)/gi, "$1: [REDACTED:CREDENTIAL]");
  out = out.replace(/\b(password|passphrase|secret)\s+(is|was|set to|=|:)\s+(\S+)/gi, "$1 $2 [REDACTED:PASSWORD]");
  out = out.replace(/\bsecret\s+([A-Za-z0-9+/]{16,})\b/g, "secret [REDACTED:SECRET]");
  out = out.replace(/\b(key|token|secret|credential)\s+\(([A-Za-z0-9+/\-_]{12,})\)/gi, "$1 ([REDACTED:CREDENTIAL])");
  out = out.replace(/(password|passphrase).*?\bset to\s+(\S+)/gi, (m, kw, val) => m.replace(val, "[REDACTED:PASSWORD]"));
  out = out.replace(/(#\s*(?:password|pass|passwd)\s*[:=]\s*)(\S+)/gi, "$1[REDACTED:PASSWORD]");
  out = out.replace(/(curl\s+.*?-u\s+)([^:\s]+):(\S+)/gi, "$1$2:[REDACTED:CREDENTIAL]");
  out = out.replace(/(sshpass\s+-p\s+)(\S+)/gi, "$1[REDACTED:CREDENTIAL]");
  out = out.replace(/(heroku\s+auth:token\s*\n)(\S+)/gi, "$1[REDACTED:TOKEN]");
  out = out.replace(
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gi,
    "[REDACTED:PRIVATE_KEY]"
  );
  out = out.replace(/\bgh[posr]_[A-Za-z0-9]{36,}\b/g, "[REDACTED:TOKEN]");
  out = out.replace(/\bnpm_[A-Za-z0-9]{36,}\b/g, "[REDACTED:TOKEN]");
  out = out.replace(/\bsk_(live|test)_[A-Za-z0-9]{24,}\b/g, "[REDACTED:TOKEN]");
  out = out.replace(/\bsk-[A-Za-z0-9\-_]{20,}\b/g, "[REDACTED:TOKEN]");
  out = out.replace(/\bxox[bpoa]-[A-Za-z0-9\-]{10,}\b/g, "[REDACTED:TOKEN]");
  out = out.replace(/\bey[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b/g, "[REDACTED:TOKEN]");
  out = out.replace(/(Authorization:\s*Bearer\s+)\S+/gi, "$1[REDACTED:TOKEN]");
  out = out.replace(
    /\b(API_KEY|SECRET_KEY|SECRET|PRIVATE_KEY|ACCESS_TOKEN|AUTH_TOKEN|JWT_SECRET|MASTER_KEY|SIGNING_KEY|ENCRYPTION_KEY|NEXTAUTH_SECRET|RAILS_MASTER_KEY|APP_SECRET|CLIENT_SECRET|WEBHOOK_SECRET|SENDGRID_API_KEY|DATADOG_API_KEY|FIREBASE_[A-Z_]+_KEY)\s*=\s*\S+/g,
    (m, varname) => `${varname}=[REDACTED:CREDENTIAL]`
  );
  out = out.replace(
    /\b[A-Z][A-Z0-9_]*(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_PASS|_PWD|_AUTH|_CREDENTIAL|_APIKEY)\s*=\s*\S+/g,
    (m) => m.replace(/=\S+$/, "=[REDACTED:CREDENTIAL]")
  );
  out = out.replace(/(grep\s+[A-Z_]*(?:SECRET|PASSWORD|TOKEN|KEY|PASS|PWD)=)(\S+)/gi, "$1[REDACTED:CREDENTIAL]");
  out = out.replace(/(scp\s+.*?\s+\S+:)([^@\s]+)(@\S+)/gi, "$1[REDACTED:CREDENTIAL]$3");
  out = out.replace(
    /\b([a-zA-Z0-9._-]{2,32}):([\S]{8,})(?=\s*[@()\s,]|$)/g,
    (m, user, pass) => {
      const hasSpecial = /[^a-zA-Z0-9]/.test(pass);
      const hasMixedDigits = /[A-Za-z]/.test(pass) && /\d/.test(pass);
      const isLong = pass.length >= 16;
      if (hasSpecial || hasMixedDigits || isLong) {
        return `${user}:[REDACTED:CREDENTIAL]`;
      }
      return m;
    }
  );
  return out;
}
async function desensitizeWithLocalModel(content, config, sessionKey) {
  if (!config.localModel?.enabled) {
    return { desensitized: content, wasModelUsed: false, failed: true };
  }
  const preRedacted = preRedactCredentials(content);
  try {
    const endpoint = config.localModel?.endpoint ?? "http://localhost:11434";
    const model = config.localModel?.model ?? "openbmb/minicpm4.1";
    const providerType = config.localModel?.type ?? "openai-compatible";
    const customModule = config.localModel?.module;
    const piiItems = await extractPiiWithModel(endpoint, model, preRedacted, {
      apiKey: config.localModel?.apiKey,
      providerType,
      customModule,
      sessionKey,
      provider: config.localModel?.provider
    });
    if (piiItems.length === 0) {
      return { desensitized: preRedacted, wasModelUsed: true };
    }
    let redacted = preRedacted;
    const sorted = [...piiItems].sort((a, b) => b.value.length - a.value.length);
    for (const item of sorted) {
      if (!item.value || item.value.length < 2) continue;
      const tag = mapPiiTypeToTag(item.type);
      redacted = replaceAll(redacted, item.value, tag);
    }
    return { desensitized: redacted, wasModelUsed: true };
  } catch (err) {
    console.error("[GuardClaw] Local model desensitization failed:", err);
    return { desensitized: preRedacted, wasModelUsed: false, failed: true };
  }
}
function mapPiiTypeToTag(type) {
  const t = type.toUpperCase().replace(/\s+/g, "_");
  const mapping = {
    ADDRESS: "[REDACTED:ADDRESS]",
    ACCESS_CODE: "[REDACTED:ACCESS_CODE]",
    DELIVERY: "[REDACTED:DELIVERY]",
    COURIER_NUMBER: "[REDACTED:DELIVERY]",
    COURIER_NO: "[REDACTED:DELIVERY]",
    COURIER_CODE: "[REDACTED:DELIVERY]",
    TRACKING_NUMBER: "[REDACTED:DELIVERY]",
    NAME: "[REDACTED:NAME]",
    SENDER_NAME: "[REDACTED:NAME]",
    RECIPIENT_NAME: "[REDACTED:NAME]",
    PHONE: "[REDACTED:PHONE]",
    SENDER_PHONE: "[REDACTED:PHONE]",
    FACILITY_PHONE: "[REDACTED:PHONE]",
    LANDLINE: "[REDACTED:PHONE]",
    MOBILE: "[REDACTED:PHONE]",
    EMAIL: "[REDACTED:EMAIL]",
    ID: "[REDACTED:ID]",
    ID_CARD: "[REDACTED:ID]",
    ID_NUMBER: "[REDACTED:ID]",
    CARD: "[REDACTED:CARD]",
    BANK_CARD: "[REDACTED:CARD]",
    CARD_NUMBER: "[REDACTED:CARD]",
    SECRET: "[REDACTED:SECRET]",
    PASSWORD: "[REDACTED:SECRET]",
    API_KEY: "[REDACTED:SECRET]",
    TOKEN: "[REDACTED:SECRET]",
    IP: "[REDACTED:IP]",
    LICENSE_PLATE: "[REDACTED:LICENSE]",
    PLATE: "[REDACTED:LICENSE]",
    TIME: "[REDACTED:TIME]",
    DATE: "[REDACTED:DATE]",
    SALARY: "[REDACTED:SALARY]",
    AMOUNT: "[REDACTED:AMOUNT]",
    // Credential types
    AWS_KEY: "[REDACTED:CREDENTIAL]",
    PRIVATE_KEY: "[REDACTED:PRIVATE_KEY]",
    CONNECTION_STRING: "[REDACTED:CREDENTIAL]",
    ENV_VAR: "[REDACTED:CREDENTIAL]",
    CREDENTIAL: "[REDACTED:CREDENTIAL]",
    MFA_CODE: "[REDACTED:SECRET]",
    CERT: "[REDACTED:CREDENTIAL]"
  };
  return mapping[t] ?? `[REDACTED:${t}]`;
}
function replaceAll(str, search, replacement) {
  const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return str.replace(new RegExp(escaped, "g"), replacement);
}
var DEFAULT_PII_EXTRACTION_PROMPT = `You are a PII extraction engine. Extract ALL PII (personally identifiable information) from the given text as a JSON array.

Types: NAME (every person), PHONE, ADDRESS (all variants including shortened), ACCESS_CODE (gate/door/\u95E8\u7981\u7801), DELIVERY (tracking numbers, pickup codes/\u53D6\u4EF6\u7801), ID (SSN/\u8EAB\u4EFD\u8BC1), CARD (bank/medical/insurance), LICENSE_PLATE (plate numbers/\u8F66\u724C), EMAIL, PASSWORD, PAYMENT (Venmo/PayPal/\u652F\u4ED8\u5B9D), BIRTHDAY, TIME (appointment/delivery times), NOTE (private instructions)

Important: Extract EVERY person's name and EVERY address variant.

Example:
Input: Alex lives at 123 Main St. Li Na phone 13912345678, gate code 1234#, card YB330-123, plate \u4EACA12345, tracking SF123, Venmo @alex99
Output: [{"type":"NAME","value":"Alex"},{"type":"NAME","value":"Li Na"},{"type":"ADDRESS","value":"123 Main St"},{"type":"PHONE","value":"13912345678"},{"type":"ACCESS_CODE","value":"1234#"},{"type":"CARD","value":"YB330-123"},{"type":"LICENSE_PLATE","value":"\u4EACA12345"},{"type":"DELIVERY","value":"SF123"},{"type":"PAYMENT","value":"@alex99"}]

Output ONLY the JSON array \u2014 no explanation, no markdown fences.`;
async function extractPiiWithModel(endpoint, model, content, opts) {
  const textSnippet = content.slice(0, 3e3);
  const systemPrompt = loadPromptWithVars("pii-extraction", DEFAULT_PII_EXTRACTION_PROMPT, {
    CONTENT: textSnippet
  });
  const promptHasContent = systemPrompt.includes(textSnippet) && textSnippet.length > 10;
  const userMessage = promptHasContent ? "Extract all PII from the text above. Output ONLY the JSON array." : textSnippet;
  const result = await callChatCompletion(
    endpoint,
    model,
    [
      { role: "system", content: systemPrompt },
      { role: "user", content: userMessage }
    ],
    {
      temperature: 0,
      maxTokens: 2500,
      stop: ["Input:", "Task:"],
      apiKey: opts?.apiKey,
      disableThinking: false,
      providerType: opts?.providerType,
      customModule: opts?.customModule
    }
  );
  if (result.usage) {
    const collector = getGlobalCollector();
    collector?.record({
      sessionKey: opts?.sessionKey ?? "",
      provider: "edge",
      model,
      source: "router",
      usage: result.usage
    });
    recordRouterOperation(opts?.sessionKey, "desensitization", result.usage, model, opts?.provider);
  }
  return parsePiiJson(result.text);
}
function parsePiiJson(raw) {
  let cleaned = raw.replace(/\s+/g, " ").trim();
  cleaned = cleaned.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "").trim();
  const arrayStart = cleaned.indexOf("[");
  if (arrayStart < 0) return [];
  let jsonStr = cleaned.slice(arrayStart);
  const lastBracket = jsonStr.lastIndexOf("]");
  if (lastBracket >= 0) {
    jsonStr = jsonStr.slice(0, lastBracket + 1);
  } else {
    const lastCloseBrace = jsonStr.lastIndexOf("}");
    if (lastCloseBrace >= 0) {
      jsonStr = jsonStr.slice(0, lastCloseBrace + 1) + "]";
    } else {
      return [];
    }
  }
  jsonStr = jsonStr.replace(/,\s*\]/g, "]");
  jsonStr = jsonStr.replace(/(?<=[\[,{]\s*)'([^']+?)'(?=\s*:)/g, '"$1"').replace(/(?<=:\s*)'([^']*?)'(?=\s*[,}\]])/g, '"$1"');
  try {
    const arr = JSON.parse(jsonStr);
    if (!Array.isArray(arr)) return [];
    const items = arr.filter(
      (item) => item && typeof item === "object" && typeof item.type === "string" && typeof item.value === "string"
    );
    return items;
  } catch {
    console.error("[GuardClaw] Failed to parse PII extraction JSON:", jsonStr.slice(0, 300));
    return [];
  }
}
function parseModelResponse(response) {
  try {
    const jsonMatch = response.match(/\{[\s\S]*?\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      const level = parsed.level?.toUpperCase();
      if (level === "S1" || level === "S2" || level === "S3") {
        return {
          level,
          reason: parsed.reason,
          confidence: parsed.confidence
        };
      }
    }
    const upperResponse = response.toUpperCase();
    if (upperResponse.includes("S3") || upperResponse.includes("PRIVATE")) {
      return {
        level: "S3",
        reason: "Detected from text analysis",
        confidence: 0.6
      };
    }
    if (upperResponse.includes("S2") || upperResponse.includes("SENSITIVE")) {
      return {
        level: "S2",
        reason: "Detected from text analysis",
        confidence: 0.6
      };
    }
    return {
      level: "S1",
      reason: "Unable to parse model response",
      confidence: 0.3
    };
  } catch (err) {
    console.error("[GuardClaw] Error parsing model response:", err);
    return {
      level: "S1",
      reason: "Parse error",
      confidence: 0
    };
  }
}

export {
  guardClawConfigSchema,
  defaultPrivacyConfig,
  defaultInjectionConfig,
  loadPrompt,
  writePrompt,
  readPromptFromDisk,
  getCorrections,
  addCorrection,
  deleteCorrection,
  levelToNumeric,
  maxLevel,
  finalizeLoop,
  getCurrentLoopHighestLevel,
  markSessionAsPrivate,
  isSessionMarkedPrivate,
  resetTurnLevel,
  recordDetection,
  clearSessionState,
  getAllSessionStates,
  stashDetection,
  getPendingDetection,
  consumeDetection,
  trackSessionLevel,
  setActiveLocalRouting,
  clearActiveLocalRouting,
  isActiveLocalRouting,
  setLastSenderId,
  getLastSenderId,
  clearLastSenderId,
  injectionAttemptCounts,
  initLiveConfig,
  watchConfigFile,
  getLiveConfig,
  getLiveInjectionConfig,
  updateLiveConfig,
  updateLiveInjectionConfig,
  TokenStatsCollector,
  setGlobalCollector,
  getGlobalCollector,
  recordFinalReply,
  getLastTurnTokens,
  getLastReplyModelOrigin,
  getLastReplyLoopSummary,
  callChatCompletion,
  detectByLocalModel,
  DEFAULT_DETECTION_SYSTEM_PROMPT,
  desensitizeWithLocalModel,
  DEFAULT_PII_EXTRACTION_PROMPT
};
