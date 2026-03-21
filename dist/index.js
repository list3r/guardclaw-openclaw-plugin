import {
  DEFAULT_DETECTION_SYSTEM_PROMPT,
  DEFAULT_PII_EXTRACTION_PROMPT,
  TokenStatsCollector,
  addCorrection,
  callChatCompletion,
  clearActiveLocalRouting,
  clearSessionState,
  consumeDetection,
  defaultPrivacyConfig,
  deleteCorrection,
  desensitizeWithLocalModel,
  detectByLocalModel,
  finalizeLoop,
  getAllSessionStates,
  getCorrections,
  getCurrentLoopHighestLevel,
  getGlobalCollector,
  getLastReplyLoopSummary,
  getLastReplyModelOrigin,
  getLastTurnTokens,
  getLiveConfig,
  getPendingDetection,
  guardClawConfigSchema,
  initLiveConfig,
  isActiveLocalRouting,
  isSessionMarkedPrivate,
  levelToNumeric,
  loadPrompt,
  markSessionAsPrivate,
  maxLevel,
  readPromptFromDisk,
  recordDetection,
  recordFinalReply,
  resetTurnLevel,
  setActiveLocalRouting,
  setGlobalCollector,
  stashDetection,
  trackSessionLevel,
  updateLiveConfig,
  watchConfigFile,
  writePrompt
} from "./chunk-K5KG73QH.js";

// index.ts
import { join as join5 } from "path";
import { readFileSync as readFileSync3, writeFileSync as writeFileSync3, mkdirSync as mkdirSync3, existsSync as existsSync3 } from "fs";

// src/hooks.ts
import * as fs3 from "fs";
import * as path3 from "path";

// src/guard-agent.ts
function isGuardAgentConfigured(config) {
  return Boolean(
    config.guardAgent?.id && config.guardAgent?.model && config.guardAgent?.workspace
  );
}
function getGuardAgentConfig(config) {
  if (!isGuardAgentConfigured(config)) {
    return null;
  }
  const fullModel = config.guardAgent?.model ?? "ollama/openbmb/minicpm4.1";
  const firstSlash = fullModel.indexOf("/");
  const defaultProvider = config.localModel?.provider ?? "ollama";
  const [provider, modelName] = firstSlash >= 0 ? [fullModel.slice(0, firstSlash), fullModel.slice(firstSlash + 1)] : [defaultProvider, fullModel];
  return {
    id: config.guardAgent?.id ?? "guard",
    model: fullModel,
    workspace: config.guardAgent?.workspace ?? "~/.openclaw/workspace-guard",
    provider,
    modelName
  };
}
function isGuardSessionKey(sessionKey) {
  return sessionKey.endsWith(":guard") || sessionKey.includes(":guard:");
}
function buildMainSessionPlaceholder(level, reason, timestamp) {
  const emoji = level === "S3" ? "\u{1F512}" : "\u{1F511}";
  const levelLabel = level === "S3" ? "Private" : "Sensitive";
  const reasonSuffix = reason ? ` (${reason})` : "";
  const tsSuffix = timestamp ? ` [ts=${new Date(timestamp).toISOString()}]` : "";
  return `${emoji} [${levelLabel} message \u2014 processed locally${reasonSuffix}]${tsSuffix}`;
}
var BUILTIN_LOCAL_PROVIDERS = [
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
];
function isLocalProvider(provider, extraProviders) {
  const lower = provider.toLowerCase();
  if (BUILTIN_LOCAL_PROVIDERS.includes(lower)) return true;
  if (extraProviders?.some((p) => p.toLowerCase() === lower)) return true;
  return false;
}

// src/sync-detect.ts
import { fileURLToPath } from "url";
import { createSyncFn } from "synckit";
var FALLBACK_S1 = {
  level: "S1",
  levelNumeric: 1,
  reason: "LLM sync detection unavailable",
  detectorType: "localModelDetector",
  confidence: 0
};
var workerPath = fileURLToPath(new URL("./llm-detect-worker.js", import.meta.url));
var _syncDetect = null;
function getSyncDetect() {
  if (!_syncDetect) {
    _syncDetect = createSyncFn(workerPath, { timeout: 2e4 });
  }
  return _syncDetect;
}
function syncDetectByLocalModel(context, config) {
  try {
    return getSyncDetect()(context, config);
  } catch (err) {
    console.warn("[GuardClaw] syncDetect fallback to S1:", err?.message?.slice(0, 120));
    return FALLBACK_S1;
  }
}

// src/memory-isolation.ts
import * as fs from "fs";
import * as path from "path";

// src/utils.ts
function normalizePath(path4) {
  if (path4.startsWith("~/")) {
    const home = process.env.HOME || process.env.USERPROFILE || "~";
    return path4.replace("~", home);
  }
  return path4;
}
function matchesPathPattern(path4, patterns) {
  const normalizedPath = normalizePath(path4);
  for (const pattern of patterns) {
    const normalizedPattern = normalizePath(pattern);
    if (normalizedPath === normalizedPattern) {
      return true;
    }
    if (normalizedPath.startsWith(normalizedPattern + "/") || normalizedPath.startsWith(normalizedPattern + "\\")) {
      return true;
    }
    if (pattern.startsWith("*") && normalizedPath.endsWith(pattern.slice(1))) {
      return true;
    }
  }
  return false;
}
function extractPathsFromParams(params) {
  const paths = [];
  const pathKeys = ["path", "file", "filepath", "filename", "dir", "directory", "target", "source"];
  for (const key of pathKeys) {
    const value = params[key];
    if (typeof value === "string" && value.trim()) {
      paths.push(value.trim());
    }
  }
  const commandKeys = ["command", "cmd", "script"];
  for (const key of commandKeys) {
    const value = params[key];
    if (typeof value === "string" && value.trim()) {
      paths.push(...extractPathsFromCommand(value));
    }
  }
  for (const value of Object.values(params)) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      paths.push(...extractPathsFromParams(value));
    }
  }
  return paths;
}
function extractPathsFromCommand(command) {
  const pathRegex = /(?:\/[\w.\-]+(?:\/[\w.\-]*)*|~\/[\w.\-]+(?:\/[\w.\-]*)*)/g;
  const matches = command.match(pathRegex);
  return matches ?? [];
}
function redactSensitiveInfo(text, opts) {
  let redacted = text;
  redacted = redacted.replace(
    /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    "[REDACTED:PRIVATE_KEY]"
  );
  redacted = redacted.replace(/\b(?:sk|key|token)-[A-Za-z0-9]{16,}\b/g, "[REDACTED:KEY]");
  redacted = redacted.replace(/AKIA[0-9A-Z]{16}/g, "[REDACTED:AWS_KEY]");
  redacted = redacted.replace(
    /(?:mysql|postgres|postgresql|mongodb|redis|amqp):\/\/[^\s"']+/gi,
    "[REDACTED:DB_CONNECTION]"
  );
  if (opts?.internalIp) {
    redacted = redacted.replace(
      /\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b/g,
      "[REDACTED:INTERNAL_IP]"
    );
  }
  if (opts?.email) {
    redacted = redacted.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "[REDACTED:EMAIL]");
  }
  if (opts?.envVar) {
    redacted = redacted.replace(
      /^(?:export\s+)?[A-Z_]{2,}=(?:["'])?[^\s"']+(?:["'])?$/gm,
      "[REDACTED:ENV_VAR]"
    );
  }
  if (opts?.creditCard) {
    redacted = redacted.replace(
      /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b/g,
      "[REDACTED:CARD_NUMBER]"
    );
  }
  if (opts?.chinesePhone) {
    redacted = redacted.replace(/(?<!\d)1[3-9]\d{9}(?!\d)/g, "[REDACTED:PHONE]");
  }
  if (opts?.chineseId) {
    redacted = redacted.replace(/(?<!\d)\d{17}[\dXx](?!\d)/g, "[REDACTED:ID]");
  }
  redacted = redacted.replace(
    /(?:快递单号|运单号|取件码)[：:\s]*[A-Za-z0-9]{6,20}/g,
    "[REDACTED:DELIVERY]"
  );
  redacted = redacted.replace(
    /(?:门禁码|门禁密码|门锁密码|开门密码)[：:\s]*[A-Za-z0-9#*]{3,12}/g,
    "[REDACTED:ACCESS_CODE]"
  );
  if (opts?.chineseAddress) {
    redacted = redacted.replace(
      /[\u4e00-\u9fa5]{2,}(?:省|市|区|县|镇|路|街|巷|弄|号|栋|幢|室|楼|单元|门牌)\d*[\u4e00-\u9fa5\d]*/g,
      "[REDACTED:ADDRESS]"
    );
  }
  const STRICT_CONNECT = "(?:\\s+(?:is|are|was|were)(?:\\s+(?:in|at|on|of|for))*|\\s*[=:])\\s*";
  const LOOSE_CONNECT = "(?:\\s+(?:is|are|was|were)(?:\\s+(?:in|at|on|of|for))*\\s*|\\s*[=:]\\s*|\\s+)";
  const contextualRules = [
    {
      pattern: new RegExp(`(?:password|passwd|pwd|passcode)${LOOSE_CONNECT}["']?([^\\s"']{2,})["']?`, "gi"),
      label: "PASSWORD"
    },
    {
      pattern: new RegExp(`(?:credit\\s*card|card\\s*(?:number|no\\.?))${STRICT_CONNECT}["']?([^\\s"']{2,})["']?`, "gi"),
      label: "CARD"
    },
    {
      pattern: new RegExp(`(?:api[_\\s]?key|access[_\\s]?key|SECRET_KEY|API_KEY)${LOOSE_CONNECT}["']?([^\\s"']{2,})["']?`, "gi"),
      label: "API_KEY"
    },
    {
      pattern: new RegExp(`(?:secret)${STRICT_CONNECT}["']?([^\\s"']{2,})["']?`, "gi"),
      label: "SECRET"
    },
    {
      pattern: new RegExp(`(?:(?:auth[_\\s]?)?token|bearer)${LOOSE_CONNECT}["']?([^\\s"']{2,})["']?`, "gi"),
      label: "TOKEN"
    },
    {
      pattern: new RegExp(`(?:credential|cred)s?${LOOSE_CONNECT}["']?([^\\s"']{2,})["']?`, "gi"),
      label: "CREDENTIAL"
    },
    {
      pattern: new RegExp(`(?:ssn|social\\s*security(?:\\s*(?:number|no\\.?))?)${STRICT_CONNECT}["']?([^\\s"']{2,})["']?`, "gi"),
      label: "SSN"
    }
  ];
  if (opts?.pin) {
    contextualRules.push({
      pattern: new RegExp(`(?:pin(?:\\s*(?:code|number))?)${STRICT_CONNECT}["']?([^\\s"']{2,})["']?`, "gi"),
      label: "PIN"
    });
  }
  for (const rule of contextualRules) {
    redacted = redacted.replace(rule.pattern, `[REDACTED:${rule.label}]`);
  }
  return redacted;
}
function isProtectedMemoryPath(filePath, baseDir = "~/.openclaw") {
  const normalizedFile = normalizePath(filePath);
  const normalizedBase = normalizePath(baseDir);
  const escapedBase = normalizedBase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const protectedPaths = [
    `${escapedBase}/agents/[^/]+/sessions/full`,
    `${escapedBase}/[^/]+/MEMORY-FULL\\.md`,
    `${escapedBase}/[^/]+/memory-full`
  ];
  for (const regexStr of protectedPaths) {
    const regex = new RegExp(`^${regexStr}`);
    if (regex.test(normalizedFile)) {
      return true;
    }
  }
  if (normalizedFile.includes("/sessions/full/") || normalizedFile.includes("/memory-full/") || normalizedFile.endsWith("/MEMORY-FULL.md")) {
    return true;
  }
  return false;
}
function resolveDefaultBaseUrl(provider, api) {
  const p = provider.toLowerCase();
  const a = (api ?? "").toLowerCase();
  if (p === "google" || p.includes("gemini") || p.includes("vertex") || a.includes("google") || a.includes("gemini")) {
    return "https://generativelanguage.googleapis.com/v1beta";
  }
  if (p === "anthropic" || a === "anthropic-messages") {
    return "https://api.anthropic.com";
  }
  return "https://api.openai.com/v1";
}

// src/memory-isolation.ts
var GUARD_SECTION_BEGIN = "<!-- guardclaw:guard-begin -->";
var GUARD_SECTION_END = "<!-- guardclaw:guard-end -->";
var MemoryIsolationManager = class {
  workspaceDir;
  constructor(workspaceDir = "~/.openclaw/workspace") {
    this.workspaceDir = workspaceDir.startsWith("~") ? path.join(process.env.HOME || process.env.USERPROFILE || "~", workspaceDir.slice(2)) : workspaceDir;
  }
  /**
   * Get memory directory path based on model type and content type
   */
  getMemoryDir(isCloudModel) {
    const memoryType = isCloudModel ? "memory" : "memory-full";
    return path.join(this.workspaceDir, memoryType);
  }
  /**
   * Get MEMORY.md path based on model type
   */
  getMemoryFilePath(isCloudModel) {
    if (isCloudModel) {
      return path.join(this.workspaceDir, "MEMORY.md");
    } else {
      return path.join(this.workspaceDir, "MEMORY-FULL.md");
    }
  }
  /**
   * Get daily memory file path
   */
  getDailyMemoryPath(isCloudModel, date) {
    const memoryDir = this.getMemoryDir(isCloudModel);
    const today = date ?? /* @__PURE__ */ new Date();
    const dateStr = today.toISOString().split("T")[0];
    return path.join(memoryDir, `${dateStr}.md`);
  }
  /**
   * Write to memory file
   */
  async writeMemory(content, isCloudModel, options) {
    try {
      const filePath = options?.daily ? this.getDailyMemoryPath(isCloudModel) : this.getMemoryFilePath(isCloudModel);
      const dir = path.dirname(filePath);
      await fs.promises.mkdir(dir, { recursive: true });
      if (options?.append) {
        await fs.promises.appendFile(filePath, content, "utf-8");
      } else {
        await fs.promises.writeFile(filePath, content, "utf-8");
      }
    } catch (err) {
      console.error(`[GuardClaw] Failed to write memory (cloud=${isCloudModel}):`, err);
    }
  }
  /**
   * Read from memory file
   */
  async readMemory(isCloudModel, options) {
    try {
      const filePath = options?.daily ? this.getDailyMemoryPath(isCloudModel, options.date) : this.getMemoryFilePath(isCloudModel);
      if (!fs.existsSync(filePath)) {
        return "";
      }
      return await fs.promises.readFile(filePath, "utf-8");
    } catch (err) {
      console.error(`[GuardClaw] Failed to read memory (cloud=${isCloudModel}):`, err);
      return "";
    }
  }
  /**
   * Merge clean memory content into full memory so FULL is always the superset.
   * Cloud models write to MEMORY.md; this step captures those additions into
   * MEMORY-FULL.md before we sanitize back. Lines already present in FULL
   * (by trimmed content) are skipped to avoid duplicates.
   */
  async mergeCleanIntoFull(options) {
    try {
      const cleanContent = await this.readMemory(true, options);
      const fullContent = await this.readMemory(false, options);
      if (!cleanContent.trim()) {
        return 0;
      }
      const fullLines = new Set(
        fullContent.split("\n").map((l) => l.trim()).filter(Boolean)
      );
      const newLines = [];
      for (const line of cleanContent.split("\n")) {
        const trimmed = line.trim();
        if (trimmed && !fullLines.has(trimmed) && !trimmed.includes("[REDACTED:")) {
          newLines.push(line);
        }
      }
      if (newLines.length === 0) {
        return 0;
      }
      const appendBlock = `

## Cloud Session Additions
${newLines.join("\n")}
`;
      await this.writeMemory(fullContent + appendBlock, false, options);
      console.log(`[GuardClaw] Merged ${newLines.length} line(s) from clean \u2192 full`);
      return newLines.length;
    } catch (err) {
      console.error("[GuardClaw] Failed to merge clean into full:", err);
      return 0;
    }
  }
  /**
   * Sync memory from full to clean (removing guard agent content + redacting PII).
   *
   * Flow:
   *   1. Merge MEMORY.md → MEMORY-FULL.md (capture cloud model additions)
   *   2. Filter guard agent sections from MEMORY-FULL.md
   *   3. Redact PII (local model → regex fallback)
   *   4. Write result to MEMORY.md
   *
   * @param privacyConfig - When provided, PII redaction uses the local model
   *   (same `desensitizeWithLocalModel` pipeline as real-time S2 messages).
   *   If the model is unavailable or config is omitted, falls back to
   *   rule-based `redactSensitiveInfo()`.
   */
  async syncMemoryToClean(privacyConfig) {
    try {
      await this.mergeCleanIntoFull();
      const fullMemory = await this.readMemory(false);
      if (!fullMemory) {
        return;
      }
      const guardStripped = this.filterGuardContent(fullMemory);
      const cleanMemory = await this.redactContent(guardStripped, privacyConfig);
      await this.writeMemory(cleanMemory, true);
      console.log("[GuardClaw] MEMORY-FULL.md synced to MEMORY.md");
    } catch (err) {
      console.error("[GuardClaw] Failed to sync memory:", err);
    }
  }
  /**
   * Sync ALL daily memory files from memory-full/ → memory/
   * Each file goes through: merge clean→full, guard-strip, PII-redact.
   */
  async syncDailyMemoryToClean(privacyConfig) {
    let synced = 0;
    try {
      const fullDir = this.getMemoryDir(false);
      const cleanDir = this.getMemoryDir(true);
      if (!fs.existsSync(fullDir)) {
        return 0;
      }
      await fs.promises.mkdir(cleanDir, { recursive: true });
      const fullFiles = fs.existsSync(fullDir) ? (await fs.promises.readdir(fullDir)).filter((f) => f.endsWith(".md")) : [];
      const cleanFiles = fs.existsSync(cleanDir) ? (await fs.promises.readdir(cleanDir)).filter((f) => f.endsWith(".md")) : [];
      const allFiles = [.../* @__PURE__ */ new Set([...fullFiles, ...cleanFiles])];
      for (const file of allFiles) {
        try {
          const fullPath = path.join(fullDir, file);
          const cleanPath = path.join(cleanDir, file);
          await this.mergeDailyFile(fullPath, cleanPath);
          const fullContent = fs.existsSync(fullPath) ? await fs.promises.readFile(fullPath, "utf-8") : "";
          if (!fullContent.trim()) {
            continue;
          }
          const guardStripped = this.filterGuardContent(fullContent);
          const cleanContent = await this.redactContent(guardStripped, privacyConfig);
          await fs.promises.writeFile(cleanPath, cleanContent, "utf-8");
          synced++;
        } catch (fileErr) {
          console.error(`[GuardClaw] Failed to sync daily file ${file}:`, fileErr);
        }
      }
      if (synced > 0) {
        console.log(
          `[GuardClaw] Synced ${synced} daily memory file(s) from memory-full/ \u2192 memory/`
        );
      }
    } catch (err) {
      console.error("[GuardClaw] Failed to sync daily memory:", err);
    }
    return synced;
  }
  /**
   * Sync everything: long-term memory + all daily files
   */
  async syncAllMemoryToClean(privacyConfig) {
    await this.syncMemoryToClean(privacyConfig);
    await this.syncDailyMemoryToClean(privacyConfig);
  }
  /**
   * PII redaction: prefer local model, fall back to regex.
   * Public alias for use by hooks that need redaction outside the sync flow.
   */
  async redactContentPublic(text, privacyConfig) {
    return this.redactContent(text, privacyConfig);
  }
  /**
   * Shared PII redaction: prefer local model, fall back to regex.
   */
  async redactContent(text, privacyConfig) {
    const redactionOpts = privacyConfig?.redaction;
    if (privacyConfig) {
      const { desensitized, wasModelUsed } = await desensitizeWithLocalModel(text, privacyConfig);
      if (wasModelUsed && desensitized !== text) {
        console.log("[GuardClaw] PII redacted via local model");
        return desensitized;
      }
      console.log(
        `[GuardClaw] PII redacted via rules (model ${wasModelUsed ? "returned unchanged" : "unavailable"})`
      );
      return redactSensitiveInfo(text, redactionOpts);
    }
    console.log("[GuardClaw] PII redacted via rules (no config)");
    return redactSensitiveInfo(text, redactionOpts);
  }
  /**
   * Merge a single daily clean file's unique lines into the corresponding full file.
   * Operates directly on file paths — no Date conversion needed, avoids timezone issues.
   */
  async mergeDailyFile(fullPath, cleanPath) {
    try {
      if (!fs.existsSync(cleanPath)) {
        return;
      }
      const cleanContent = await fs.promises.readFile(cleanPath, "utf-8");
      if (!cleanContent.trim()) {
        return;
      }
      const fullContent = fs.existsSync(fullPath) ? await fs.promises.readFile(fullPath, "utf-8") : "";
      const fullLines = new Set(
        fullContent.split("\n").map((l) => l.trim()).filter(Boolean)
      );
      const newLines = [];
      for (const line of cleanContent.split("\n")) {
        const trimmed = line.trim();
        if (trimmed && !fullLines.has(trimmed) && !trimmed.includes("[REDACTED:")) {
          newLines.push(line);
        }
      }
      if (newLines.length === 0) {
        return;
      }
      await fs.promises.mkdir(path.dirname(fullPath), { recursive: true });
      const appendBlock = `

## Cloud Session Additions
${newLines.join("\n")}
`;
      await fs.promises.writeFile(fullPath, fullContent + appendBlock, "utf-8");
      console.log(
        `[GuardClaw] Merged ${newLines.length} daily line(s) from clean \u2192 full (${path.basename(fullPath)})`
      );
    } catch (err) {
      console.error(`[GuardClaw] Failed to merge daily file:`, err);
    }
  }
  /**
   * Filter guard agent content from memory text.
   * Uses explicit `GUARD_SECTION_BEGIN` / `GUARD_SECTION_END` HTML comment
   * markers to delimit guard-originated sections.  Falls back to the legacy
   * heuristic for content written before markers were introduced.
   */
  filterGuardContent(content) {
    const lines = content.split("\n");
    const filtered = [];
    let inGuardSection = false;
    for (const line of lines) {
      if (line.trim() === GUARD_SECTION_BEGIN) {
        inGuardSection = true;
        continue;
      }
      if (line.trim() === GUARD_SECTION_END) {
        inGuardSection = false;
        continue;
      }
      if (!inGuardSection) {
        filtered.push(line);
      }
    }
    return filtered.join("\n");
  }
  /**
   * Ensure both memory directories exist
   */
  async initializeDirectories() {
    try {
      const fullDir = this.getMemoryDir(false);
      const cleanDir = this.getMemoryDir(true);
      await fs.promises.mkdir(fullDir, { recursive: true });
      await fs.promises.mkdir(cleanDir, { recursive: true });
      console.log("[GuardClaw] Memory directories initialized");
    } catch (err) {
      console.error("[GuardClaw] Failed to initialize memory directories:", err);
    }
  }
};
var defaultMemoryManager = null;
function getDefaultMemoryManager(workspaceDir) {
  if (!defaultMemoryManager || workspaceDir) {
    defaultMemoryManager = new MemoryIsolationManager(workspaceDir);
  }
  return defaultMemoryManager;
}

// src/session-manager.ts
import * as fs2 from "fs";
import * as path2 from "path";
var DualSessionManager = class {
  baseDir;
  writeLocks = /* @__PURE__ */ new Map();
  /**
   * Serialize writes to the same file to prevent interleaved JSONL lines
   * when multiple fire-and-forget writes race from sync hooks.
   */
  async withWriteLock(lockKey, fn) {
    const prev = this.writeLocks.get(lockKey) ?? Promise.resolve();
    const next = prev.then(fn, fn);
    this.writeLocks.set(lockKey, next);
    await next;
  }
  constructor(baseDir = "~/.openclaw") {
    this.baseDir = baseDir.startsWith("~") ? path2.join(process.env.HOME || process.env.USERPROFILE || "~", baseDir.slice(2)) : baseDir;
  }
  /**
   * Persist a message to session history
   * - Full history: includes all messages (including guard agent interactions)
   * - Clean history: excludes guard agent interactions (for cloud models)
   */
  async persistMessage(sessionKey, message, agentId = "main") {
    await this.writeToHistory(sessionKey, message, agentId, "full");
    if (!this.isGuardAgentMessage(message)) {
      await this.writeToHistory(sessionKey, message, agentId, "clean");
    }
  }
  /**
   * Seed the full track with existing clean track content (if any) so that
   * the full track is a complete history from the start of the session.
   * No-op if the full track already exists.  Mirrors the memory-isolation
   * pattern of mergeCleanIntoFull.
   */
  seededSessions = /* @__PURE__ */ new Set();
  async ensureFullTrackSeeded(sessionKey, agentId) {
    const key = `${sessionKey}:${agentId}`;
    if (this.seededSessions.has(key)) return;
    const fullPath = this.getHistoryPath(sessionKey, agentId, "full");
    if (fs2.existsSync(fullPath)) {
      this.seededSessions.add(key);
      return;
    }
    const cleanPath = this.getHistoryPath(sessionKey, agentId, "clean");
    if (!fs2.existsSync(cleanPath)) {
      this.seededSessions.add(key);
      return;
    }
    try {
      const dir = path2.dirname(fullPath);
      await fs2.promises.mkdir(dir, { recursive: true });
      await fs2.promises.copyFile(cleanPath, fullPath);
      console.log(`[GuardClaw] Seeded full track from clean track for ${sessionKey}`);
    } catch (err) {
      console.error(`[GuardClaw] Failed to seed full track for ${sessionKey}:`, err);
    }
    this.seededSessions.add(key);
  }
  /**
   * Write a message to the full history only.
   * On first write, seeds the full track with existing clean track content
   * so it contains the complete conversation history.
   */
  async writeToFull(sessionKey, message, agentId = "main") {
    await this.ensureFullTrackSeeded(sessionKey, agentId);
    await this.writeToHistory(sessionKey, message, agentId, "full");
  }
  /**
   * Write a message to the clean history only.
   */
  async writeToClean(sessionKey, message, agentId = "main") {
    await this.writeToHistory(sessionKey, message, agentId, "clean");
  }
  /**
   * Load session history based on model type
   * - Cloud models: get clean history only
   * - Local models: get full history
   */
  async loadHistory(sessionKey, isCloudModel, agentId = "main", limit) {
    const historyType = isCloudModel ? "clean" : "full";
    return await this.readHistory(sessionKey, agentId, historyType, limit);
  }
  /**
   * Check if a message is from guard agent interactions
   */
  isGuardAgentMessage(message) {
    if (message.sessionKey && isGuardSessionKey(message.sessionKey)) {
      return true;
    }
    const content = message.content;
    if (content.includes("[guardclaw:guard]") || content.includes("[guard agent]")) {
      return true;
    }
    return false;
  }
  /**
   * Write message to history file.
   * Uses a per-file write lock to serialize concurrent appends
   * (e.g. from fire-and-forget calls in sync hooks).
   */
  async writeToHistory(sessionKey, message, agentId, historyType) {
    const historyPath = this.getHistoryPath(sessionKey, agentId, historyType);
    await this.withWriteLock(historyPath, async () => {
      try {
        const dir = path2.dirname(historyPath);
        await fs2.promises.mkdir(dir, { recursive: true });
        const line = JSON.stringify({
          ...message,
          timestamp: message.timestamp ?? Date.now()
        });
        await fs2.promises.appendFile(historyPath, line + "\n", "utf-8");
      } catch (err) {
        console.error(
          `[GuardClaw] Failed to write to ${historyType} history for ${sessionKey}:`,
          err
        );
      }
    });
  }
  /**
   * Read messages from history file
   */
  async readHistory(sessionKey, agentId, historyType, limit) {
    try {
      const historyPath = this.getHistoryPath(sessionKey, agentId, historyType);
      if (!fs2.existsSync(historyPath)) {
        return [];
      }
      const content = await fs2.promises.readFile(historyPath, "utf-8");
      const lines = content.trim().split("\n").filter(Boolean);
      const messages = lines.map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      }).filter((msg) => msg !== null);
      if (limit && messages.length > limit) {
        return messages.slice(-limit);
      }
      return messages;
    } catch (err) {
      console.error(
        `[GuardClaw] Failed to read ${historyType} history for ${sessionKey}:`,
        err
      );
      return [];
    }
  }
  /**
   * Get history file path
   */
  getHistoryPath(sessionKey, agentId, historyType) {
    const safeSessionKey = sessionKey.replace(/[^a-zA-Z0-9_-]/g, "_");
    const fileName = `${safeSessionKey}.jsonl`;
    return path2.join(
      this.baseDir,
      "agents",
      agentId,
      "sessions",
      historyType,
      fileName
    );
  }
  /**
   * Clear history for a session
   */
  async clearHistory(sessionKey, agentId = "main", historyType) {
    const types = historyType ? [historyType] : ["full", "clean"];
    for (const type of types) {
      try {
        const historyPath = this.getHistoryPath(sessionKey, agentId, type);
        if (fs2.existsSync(historyPath)) {
          await fs2.promises.unlink(historyPath);
        }
      } catch (err) {
        console.error(
          `[GuardClaw] Failed to clear ${type} history for ${sessionKey}:`,
          err
        );
      }
    }
  }
  /**
   * Load messages that exist in the full track but not in the clean track.
   * These are Guard Agent interactions and original S3 content that were
   * stripped from the sanitized transcript — exactly the context a local
   * model needs to reconstruct the full conversation.
   */
  async loadHistoryDelta(sessionKey, agentId = "main", limit) {
    const full = await this.readHistory(sessionKey, agentId, "full");
    const clean = await this.readHistory(sessionKey, agentId, "clean");
    if (full.length === 0) return [];
    if (clean.length === 0) return limit ? full.slice(-limit) : full;
    const cleanSet = new Set(
      clean.map((m) => `${m.role}:${m.timestamp ?? ""}:${m.content.slice(0, 80)}`)
    );
    const delta = full.filter(
      (m) => !cleanSet.has(`${m.role}:${m.timestamp ?? ""}:${m.content.slice(0, 80)}`)
    );
    return limit && delta.length > limit ? delta.slice(-limit) : delta;
  }
  /**
   * Format session messages as a readable conversation context block
   * suitable for injection via prependContext.
   */
  static formatAsContext(messages, label) {
    if (messages.length === 0) return "";
    const header = label ?? "Full conversation history (original, authoritative)";
    const lines = [
      `[${header}]`,
      `[NOTE: The conversation above may contain "\u{1F512} [Private message]" placeholders or redacted text. This is the complete original history \u2014 use it as the authoritative source.]`
    ];
    for (const msg of messages) {
      const roleLabel = msg.role === "user" ? "User" : msg.role === "assistant" ? "Assistant" : msg.role === "tool" ? `Tool${msg.toolName ? `(${msg.toolName})` : ""}` : "System";
      const ts = msg.timestamp ? ` [ts=${new Date(msg.timestamp).toISOString()}]` : "";
      const truncated = msg.content.length > 2e3 ? msg.content.slice(0, 2e3) + "\u2026(truncated)" : msg.content;
      lines.push(`${roleLabel}${ts}: ${truncated}`);
    }
    lines.push("[End of private context]");
    return lines.join("\n");
  }
  /**
   * Get history statistics
   */
  async getHistoryStats(sessionKey, agentId = "main") {
    const full = await this.readHistory(sessionKey, agentId, "full");
    const clean = await this.readHistory(sessionKey, agentId, "clean");
    return {
      fullCount: full.length,
      cleanCount: clean.length,
      difference: full.length - clean.length
    };
  }
};
var defaultManager = null;
function getDefaultSessionManager(baseDir) {
  if (!defaultManager || baseDir) {
    defaultManager = new DualSessionManager(baseDir);
  }
  return defaultManager;
}

// src/rules.ts
var PATTERN_CACHE_MAX = 500;
var patternCache = /* @__PURE__ */ new Map();
function getOrCompileRegex(pattern) {
  const cached = patternCache.get(pattern);
  if (cached) return cached;
  try {
    let flags = "i";
    const cleaned = pattern.replace(/^\(\?([gimsuy]+)\)/, (_m, f) => {
      flags = f.includes("i") ? "i" : "";
      if (f.includes("s")) flags += "s";
      if (f.includes("m")) flags += "m";
      return "";
    });
    const compiled = new RegExp(cleaned, flags);
    if (patternCache.size >= PATTERN_CACHE_MAX) {
      const firstKey = patternCache.keys().next().value;
      if (firstKey !== void 0) patternCache.delete(firstKey);
    }
    patternCache.set(pattern, compiled);
    return compiled;
  } catch (err) {
    console.warn(`[GuardClaw] Invalid regex pattern: ${pattern} \u2014 ${err.message}`);
    return null;
  }
}
function detectByRules(context, config) {
  const levels = [];
  const reasons = [];
  if (context.message) {
    const keywordResult = checkKeywords(context.message, config);
    if (keywordResult.level !== "S1") {
      levels.push(keywordResult.level);
      if (keywordResult.reason) {
        reasons.push(keywordResult.reason);
      }
    }
  }
  if (context.message) {
    const patternResult = checkPatterns(context.message, config);
    if (patternResult.level !== "S1") {
      levels.push(patternResult.level);
      if (patternResult.reason) {
        reasons.push(patternResult.reason);
      }
    }
  }
  if (context.toolName) {
    const toolResult = checkToolType(context.toolName, config);
    if (toolResult.level !== "S1") {
      levels.push(toolResult.level);
      if (toolResult.reason) {
        reasons.push(toolResult.reason);
      }
    }
  }
  if (context.toolParams) {
    const paramResult = checkToolParams(context.toolParams, config);
    if (paramResult.level !== "S1") {
      levels.push(paramResult.level);
      if (paramResult.reason) {
        reasons.push(paramResult.reason);
      }
    }
  }
  if (context.toolResult) {
    const resultText = typeof context.toolResult === "string" ? context.toolResult : JSON.stringify(context.toolResult);
    const resultKeywordLevel = checkKeywords(resultText, config);
    if (resultKeywordLevel.level !== "S1") {
      levels.push(resultKeywordLevel.level);
      if (resultKeywordLevel.reason) {
        reasons.push(`Result: ${resultKeywordLevel.reason}`);
      }
    }
    const resultPatternLevel = checkPatterns(resultText, config);
    if (resultPatternLevel.level !== "S1") {
      levels.push(resultPatternLevel.level);
      if (resultPatternLevel.reason) {
        reasons.push(`Result: ${resultPatternLevel.reason}`);
      }
    }
  }
  const finalLevel = levels.length > 0 ? maxLevel(...levels) : "S1";
  const finalReason = reasons.length > 0 ? reasons.join("; ") : void 0;
  return {
    level: finalLevel,
    levelNumeric: levelToNumeric(finalLevel),
    reason: finalReason,
    detectorType: "ruleDetector",
    confidence: 1
    // Rules have high confidence
  };
}
var keywordRegexCache = /* @__PURE__ */ new Map();
function getKeywordRegex(keyword) {
  const cached = keywordRegexCache.get(keyword);
  if (cached) return cached;
  const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  let pattern;
  if (keyword.startsWith(".")) {
    pattern = `${escaped}(?![a-zA-Z0-9])`;
  } else {
    pattern = `(?<![a-zA-Z0-9])${escaped}(?![a-zA-Z0-9])`;
  }
  const re = new RegExp(pattern, "i");
  keywordRegexCache.set(keyword, re);
  return re;
}
function checkKeywords(text, config) {
  const s3Keywords = config.rules?.keywords?.S3 ?? [];
  for (const keyword of s3Keywords) {
    if (getKeywordRegex(keyword).test(text)) {
      return {
        level: "S3",
        reason: `S3 keyword detected: ${keyword}`
      };
    }
  }
  const s2Keywords = config.rules?.keywords?.S2 ?? [];
  for (const keyword of s2Keywords) {
    if (getKeywordRegex(keyword).test(text)) {
      return {
        level: "S2",
        reason: `S2 keyword detected: ${keyword}`
      };
    }
  }
  return { level: "S1" };
}
function checkPatterns(text, config) {
  const s3Patterns = config.rules?.patterns?.S3 ?? [];
  for (const pattern of s3Patterns) {
    const regex = getOrCompileRegex(pattern);
    if (regex && regex.test(text)) {
      return {
        level: "S3",
        reason: `S3 pattern matched: ${pattern}`
      };
    }
  }
  const s2Patterns = config.rules?.patterns?.S2 ?? [];
  for (const pattern of s2Patterns) {
    const regex = getOrCompileRegex(pattern);
    if (regex && regex.test(text)) {
      return {
        level: "S2",
        reason: `S2 pattern matched: ${pattern}`
      };
    }
  }
  return { level: "S1" };
}
function toolNameContainsSegment(name, segment) {
  const escaped = segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`(?:^|[._\\-])${escaped}(?:$|[._\\-])`, "i");
  return re.test(name);
}
function checkToolType(toolName, config) {
  const normalizedTool = toolName.toLowerCase();
  const s3Tools = config.rules?.tools?.S3?.tools ?? [];
  for (const tool of s3Tools) {
    const pattern = tool.toLowerCase();
    if (normalizedTool === pattern || toolNameContainsSegment(normalizedTool, pattern)) {
      return {
        level: "S3",
        reason: `S3 tool detected: ${toolName}`
      };
    }
  }
  const s2Tools = config.rules?.tools?.S2?.tools ?? [];
  for (const tool of s2Tools) {
    const pattern = tool.toLowerCase();
    if (normalizedTool === pattern || toolNameContainsSegment(normalizedTool, pattern)) {
      return {
        level: "S2",
        reason: `S2 tool detected: ${toolName}`
      };
    }
  }
  return { level: "S1" };
}
function checkToolParams(params, config) {
  const paths = extractPathsFromParams(params);
  if (paths.length === 0) {
    return { level: "S1" };
  }
  const s3Paths = config.rules?.tools?.S3?.paths ?? [];
  for (const path4 of paths) {
    if (matchesPathPattern(path4, s3Paths)) {
      return {
        level: "S3",
        reason: `S3 path detected: ${path4}`
      };
    }
  }
  const s2Paths = config.rules?.tools?.S2?.paths ?? [];
  for (const path4 of paths) {
    if (matchesPathPattern(path4, s2Paths)) {
      return {
        level: "S2",
        reason: `S2 path detected: ${path4}`
      };
    }
  }
  for (const path4 of paths) {
    const lowerPath = path4.toLowerCase();
    if (lowerPath.endsWith(".pem") || lowerPath.endsWith(".key") || lowerPath.endsWith(".p12") || lowerPath.endsWith(".pfx") || lowerPath.includes("id_rsa") || lowerPath.includes("id_dsa") || lowerPath.includes("id_ecdsa") || lowerPath.includes("id_ed25519")) {
      return {
        level: "S3",
        reason: `Sensitive file extension detected: ${path4}`
      };
    }
  }
  return { level: "S1" };
}

// src/privacy-proxy.ts
import * as http from "http";

// src/provider.ts
var activeProxy = null;
function setActiveProxy(proxy) {
  activeProxy = proxy;
}
var modelProviderMap = /* @__PURE__ */ new Map();
function getProviderForModel(modelId) {
  return modelProviderMap.get(modelId);
}
var guardClawPrivacyProvider = {
  id: "guardclaw-privacy",
  label: "GuardClaw Privacy Proxy",
  aliases: [],
  envVars: [],
  auth: []
};
function mirrorAllProviderModels(config, resolveApiKey) {
  const seen = /* @__PURE__ */ new Set();
  const mirrored = [];
  const providers = config.models?.providers ?? {};
  for (const [providerName, providerConfig] of Object.entries(providers)) {
    if (!providerConfig.models) continue;
    const apiKey = providerConfig.apiKey || (resolveApiKey ? resolveApiKey(providerName) : "");
    const target = {
      providerName,
      baseUrl: providerConfig.baseUrl ?? "",
      apiKey: apiKey || void 0,
      api: providerConfig.api
    };
    const models = providerConfig.models;
    if (Array.isArray(models)) {
      for (const m of models) {
        const id = m?.id;
        if (id && !seen.has(id)) {
          seen.add(id);
          mirrored.push(m);
          modelProviderMap.set(id, target);
        }
      }
    } else if (typeof models === "object" && models !== null) {
      for (const [modelId, modelDef] of Object.entries(models)) {
        if (!seen.has(modelId)) {
          seen.add(modelId);
          mirrored.push({ id: modelId, ...typeof modelDef === "object" && modelDef !== null ? modelDef : {} });
          modelProviderMap.set(modelId, target);
        }
      }
    }
  }
  return mirrored;
}

// src/privacy-proxy.ts
var GUARDCLAW_S2_OPEN = "<guardclaw-s2>";
var GUARDCLAW_S2_CLOSE = "</guardclaw-s2>";
var PROVIDER_STASH_TTL_MS = 12e4;
var originalProviderTargets = /* @__PURE__ */ new Map();
function stashOriginalProvider(key, target) {
  originalProviderTargets.set(key, { target, ts: Date.now() });
}
function getStashedProvider(key) {
  const entry = originalProviderTargets.get(key);
  if (!entry) return void 0;
  if (Date.now() - entry.ts > PROVIDER_STASH_TTL_MS) {
    originalProviderTargets.delete(key);
    return void 0;
  }
  return entry.target;
}
function cleanupStaleProviderTargets() {
  const now = Date.now();
  for (const [k, v] of originalProviderTargets) {
    if (now - v.ts > PROVIDER_STASH_TTL_MS) originalProviderTargets.delete(k);
  }
}
var _providerCleanupInterval = setInterval(cleanupStaleProviderTargets, 6e4);
if (typeof _providerCleanupInterval === "object" && "unref" in _providerCleanupInterval) {
  _providerCleanupInterval.unref();
}
var defaultProviderTarget = null;
function setDefaultProviderTarget(target) {
  defaultProviderTarget = target;
}
function readRequestBody(req) {
  return new Promise((resolve2, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve2(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}
var UNSUPPORTED_SCHEMA_KEYWORDS = /* @__PURE__ */ new Set([
  "patternProperties",
  "additionalProperties",
  "$schema",
  "$id",
  "$ref",
  "$defs",
  "definitions",
  "examples",
  "minLength",
  "maxLength",
  "minimum",
  "maximum",
  "multipleOf",
  "pattern",
  "format",
  "minItems",
  "maxItems",
  "uniqueItems",
  "minProperties",
  "maxProperties"
]);
function stripUnsupportedSchemaKeywords(obj) {
  if (!obj || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(stripUnsupportedSchemaKeywords);
  const cleaned = {};
  for (const [key, value] of Object.entries(obj)) {
    if (UNSUPPORTED_SCHEMA_KEYWORDS.has(key)) continue;
    if (value && typeof value === "object") {
      cleaned[key] = stripUnsupportedSchemaKeywords(value);
    } else {
      cleaned[key] = value;
    }
  }
  return cleaned;
}
function cleanToolSchemas(tools) {
  if (!Array.isArray(tools) || tools.length === 0) return false;
  let cleaned = false;
  for (let i = 0; i < tools.length; i++) {
    const tool = tools[i];
    if (!tool) continue;
    const fn = tool.function;
    const params = fn?.parameters;
    if (params && typeof params === "object") {
      const result = stripUnsupportedSchemaKeywords(params);
      if (result !== params) {
        fn.parameters = result;
        cleaned = true;
      }
    }
  }
  return cleaned;
}
function cleanGoogleToolSchemas(tools) {
  if (!Array.isArray(tools) || tools.length === 0) return false;
  let cleaned = false;
  for (const tool of tools) {
    if (!tool || typeof tool !== "object") continue;
    const decls = tool.functionDeclarations ?? tool.function_declarations;
    if (!Array.isArray(decls)) continue;
    for (const decl of decls) {
      if (!decl || typeof decl !== "object") continue;
      const params = decl.parameters;
      if (params && typeof params === "object") {
        decl.parameters = stripUnsupportedSchemaKeywords(params);
        cleaned = true;
      }
    }
  }
  return cleaned;
}
function stripPiiMarkers(messages) {
  let stripped = false;
  for (const msg of messages) {
    if (typeof msg.content === "string") {
      const openIdx = msg.content.indexOf(GUARDCLAW_S2_OPEN);
      const closeIdx = msg.content.indexOf(GUARDCLAW_S2_CLOSE);
      if (openIdx === -1 || closeIdx === -1 || closeIdx <= openIdx) continue;
      msg.content = msg.content.slice(openIdx + GUARDCLAW_S2_OPEN.length, closeIdx).trim();
      stripped = true;
    } else if (Array.isArray(msg.content)) {
      for (const part of msg.content) {
        if (!part || typeof part.text !== "string") continue;
        const openIdx = part.text.indexOf(GUARDCLAW_S2_OPEN);
        const closeIdx = part.text.indexOf(GUARDCLAW_S2_CLOSE);
        if (openIdx === -1 || closeIdx === -1 || closeIdx <= openIdx) continue;
        part.text = part.text.slice(openIdx + GUARDCLAW_S2_OPEN.length, closeIdx).trim();
        stripped = true;
      }
    }
  }
  return stripped;
}
function stripPiiMarkersGoogleContents(contents) {
  if (!Array.isArray(contents) || contents.length === 0) return false;
  let stripped = false;
  for (const entry of contents) {
    if (!entry || typeof entry !== "object") continue;
    const e = entry;
    const parts = e.parts;
    if (!Array.isArray(parts)) continue;
    for (const part of parts) {
      if (!part || typeof part !== "object") continue;
      const p = part;
      if (typeof p.text !== "string") continue;
      const openIdx = p.text.indexOf(GUARDCLAW_S2_OPEN);
      const closeIdx = p.text.indexOf(GUARDCLAW_S2_CLOSE);
      if (openIdx === -1 || closeIdx === -1 || closeIdx <= openIdx) continue;
      p.text = p.text.slice(openIdx + GUARDCLAW_S2_OPEN.length, closeIdx).trim();
      stripped = true;
    }
  }
  return stripped;
}
var ANTHROPIC_PATTERNS = ["anthropic"];
var ANTHROPIC_APIS = ["anthropic-messages"];
var GOOGLE_NATIVE_APIS = ["google-generative-ai", "google-gemini-cli", "google-ai-studio"];
var GOOGLE_URL_MARKERS = ["generativelanguage.googleapis.com", "aiplatform.googleapis.com"];
function isGoogleTarget(target) {
  const api = (target.api ?? "").toLowerCase();
  const provider = target.provider.toLowerCase();
  const url = target.baseUrl.toLowerCase();
  if (api === "openai-completions" || api === "openai-chat") return false;
  if (GOOGLE_NATIVE_APIS.some((p) => api.includes(p))) return true;
  if (provider === "google" || provider.includes("gemini") || provider.includes("vertex")) return true;
  if (GOOGLE_URL_MARKERS.some((p) => url.includes(p))) return true;
  return false;
}
function resolveAuthHeaders(target) {
  const headers = {};
  if (!target.apiKey) return headers;
  const p = target.provider.toLowerCase();
  const api = (target.api ?? "").toLowerCase();
  if (ANTHROPIC_PATTERNS.some((pat) => p.includes(pat)) || ANTHROPIC_APIS.includes(api)) {
    headers["x-api-key"] = target.apiKey;
    headers["anthropic-version"] = "2023-06-01";
  } else {
    headers["Authorization"] = `Bearer ${target.apiKey}`;
  }
  return headers;
}
function resolveTarget(sessionHeader, modelId) {
  if (sessionHeader) {
    const t = getStashedProvider(sessionHeader);
    if (t) return t;
  }
  if (modelId) {
    const providerTarget = getProviderForModel(modelId);
    if (providerTarget && providerTarget.baseUrl) {
      return {
        baseUrl: providerTarget.baseUrl,
        apiKey: providerTarget.apiKey ?? "",
        provider: providerTarget.providerName,
        api: providerTarget.api
      };
    }
  }
  return defaultProviderTarget;
}
function completionToSSE(responseJson) {
  const id = responseJson.id ?? "chatcmpl-proxy";
  const model = responseJson.model ?? "";
  const created = responseJson.created ?? Math.floor(Date.now() / 1e3);
  const choices = responseJson.choices ?? [];
  const chunks = [];
  for (const choice of choices) {
    const msg = choice.message;
    const content = msg?.content ?? "";
    const finishReason = choice.finish_reason ?? "stop";
    if (content) {
      chunks.push(`data: ${JSON.stringify({
        id,
        object: "chat.completion.chunk",
        created,
        model,
        choices: [{ index: choice.index ?? 0, delta: { role: "assistant", content }, finish_reason: null }]
      })}

`);
    }
    chunks.push(`data: ${JSON.stringify({
      id,
      object: "chat.completion.chunk",
      created,
      model,
      choices: [{ index: choice.index ?? 0, delta: {}, finish_reason: finishReason }],
      ...responseJson.usage ? { usage: responseJson.usage } : {}
    })}

`);
  }
  chunks.push("data: [DONE]\n\n");
  return chunks.join("");
}
function buildUpstreamUrl(targetBaseUrl, reqUrl, target) {
  let baseUrl = targetBaseUrl.replace(/\/+$/, "");
  const rawPath = reqUrl ?? "/v1/chat/completions";
  const api = (target?.api ?? "").toLowerCase();
  const isAnthropic = api === "anthropic-messages" || ANTHROPIC_PATTERNS.some((p) => (target?.provider ?? "").toLowerCase().includes(p));
  if (isAnthropic) {
    return `${baseUrl}${rawPath}`;
  }
  const forwardPath = rawPath.replace(/^\/v1/, "");
  if (target && isGoogleTarget(target) && !baseUrl.includes("/openai")) {
    baseUrl = `${baseUrl}/openai`;
  }
  return `${baseUrl}${forwardPath}`;
}
var STREAM_FIRST_CHUNK_TIMEOUT_MS = 3e4;
async function tryStreamUpstream(parsed, upstreamUrl, upstreamHeaders, res, log) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), STREAM_FIRST_CHUNK_TIMEOUT_MS);
  let upstream;
  try {
    upstream = await fetch(upstreamUrl, {
      method: "POST",
      headers: upstreamHeaders,
      body: JSON.stringify(parsed),
      signal: controller.signal
    });
  } catch {
    clearTimeout(timeout);
    return false;
  }
  if (!upstream.body || !upstream.ok) {
    clearTimeout(timeout);
    return false;
  }
  const reader = upstream.body.getReader();
  let firstRead;
  try {
    const timeoutPromise = new Promise((_, reject) => {
      const t = setTimeout(() => {
        clearTimeout(t);
        reject(new Error("stream_first_chunk_timeout"));
      }, STREAM_FIRST_CHUNK_TIMEOUT_MS);
    });
    firstRead = await Promise.race([reader.read(), timeoutPromise]);
  } catch (err) {
    clearTimeout(timeout);
    controller.abort();
    try {
      await reader.cancel();
    } catch {
    }
    try {
      reader.releaseLock();
    } catch {
    }
    if (err?.message === "stream_first_chunk_timeout") {
      log.warn(`[GuardClaw Proxy] Stream first chunk timeout (${STREAM_FIRST_CHUNK_TIMEOUT_MS}ms)`);
    }
    return false;
  }
  clearTimeout(timeout);
  if (firstRead.done) {
    return false;
  }
  const contentType = upstream.headers.get("content-type") ?? "text/event-stream";
  res.writeHead(upstream.status, {
    "Content-Type": contentType,
    "Cache-Control": "no-cache",
    "Connection": "keep-alive"
  });
  res.write(Buffer.from(firstRead.value));
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!res.writableEnded) {
        res.write(Buffer.from(value));
      }
    }
  } catch {
    log.warn("[GuardClaw Proxy] Upstream stream closed unexpectedly");
  } finally {
    if (!res.writableEnded) res.end();
  }
  return true;
}
async function startPrivacyProxy(port, logger) {
  const log = logger ?? {
    info: (m) => console.log(m),
    warn: (m) => console.warn(m),
    error: (m) => console.error(m)
  };
  const server = http.createServer(async (req, res) => {
    if (req.method !== "POST") {
      res.writeHead(405, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Method not allowed" }));
      return;
    }
    try {
      log.info(`[GuardClaw Proxy] Incoming ${req.method} ${req.url}`);
      const body = await readRequestBody(req);
      if (!body || !body.trim()) {
        log.warn("[GuardClaw Proxy] Empty request body");
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { message: "Empty request body", type: "invalid_request" } }));
        return;
      }
      let parsed;
      try {
        parsed = JSON.parse(body);
      } catch (parseErr) {
        log.warn(`[GuardClaw Proxy] Invalid JSON body: ${String(parseErr)}`);
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { message: `Invalid JSON: ${String(parseErr)}`, type: "invalid_request" } }));
        return;
      }
      const hadOpenAiMarkers = stripPiiMarkers(parsed.messages ?? []);
      const hadGoogleMarkers = stripPiiMarkersGoogleContents(parsed.contents);
      if (hadOpenAiMarkers || hadGoogleMarkers) {
        log.info("[GuardClaw Proxy] Stripped S2 PII markers from request");
      }
      const hadOpenAiSchemaFix = cleanToolSchemas(parsed.tools);
      const hadGoogleSchemaFix = cleanGoogleToolSchemas(parsed.tools);
      if (hadOpenAiSchemaFix || hadGoogleSchemaFix) {
        log.info("[GuardClaw Proxy] Cleaned unsupported keywords from tool schemas");
      }
      const redactionOpts = getLiveConfig().redaction;
      const allMessages = parsed.messages ?? parsed.contents ?? [];
      for (const msg of allMessages) {
        const role = String(msg.role ?? "").toLowerCase();
        if (role === "system") continue;
        if (typeof msg.content === "string") {
          const redacted = redactSensitiveInfo(msg.content, redactionOpts);
          if (redacted !== msg.content) {
            msg.content = redacted;
            log.info("[GuardClaw Proxy] Defense-in-depth: rule-based PII redaction applied to message");
          }
        } else if (Array.isArray(msg.content)) {
          for (const part of msg.content) {
            if (part && typeof part.text === "string") {
              const redacted = redactSensitiveInfo(part.text, redactionOpts);
              if (redacted !== part.text) {
                part.text = redacted;
                log.info("[GuardClaw Proxy] Defense-in-depth: rule-based PII redaction applied to message part");
              }
            }
          }
        }
        if (Array.isArray(msg.parts)) {
          for (const part of msg.parts) {
            if (part && typeof part.text === "string") {
              const redacted = redactSensitiveInfo(part.text, redactionOpts);
              if (redacted !== part.text) {
                part.text = redacted;
                log.info("[GuardClaw Proxy] Defense-in-depth: rule-based PII redaction applied to Google part");
              }
            }
          }
        }
      }
      const sessionKey = req.headers["x-guardclaw-session"];
      const requestModel = parsed.model;
      const target = resolveTarget(sessionKey, requestModel);
      if (!target) {
        log.error("[GuardClaw Proxy] No original provider target found");
        res.writeHead(502, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          error: {
            message: "GuardClaw privacy proxy: no original provider target configured",
            type: "proxy_error"
          }
        }));
        return;
      }
      const upstreamUrl = buildUpstreamUrl(target.baseUrl, req.url, target);
      const upstreamHeaders = {
        "Content-Type": "application/json",
        ...resolveAuthHeaders(target)
      };
      const MAX_COMPLETION_TOKENS = 16384;
      for (const key of ["max_tokens", "max_completion_tokens"]) {
        if (parsed[key] != null && parsed[key] > MAX_COMPLETION_TOKENS) {
          log.info(`[GuardClaw Proxy] Capped ${key} ${parsed[key]} \u2192 ${MAX_COMPLETION_TOKENS}`);
          parsed[key] = MAX_COMPLETION_TOKENS;
        }
      }
      const clientWantsStream = !!parsed.stream;
      const streamUpstream = clientWantsStream;
      log.info(`[GuardClaw Proxy] \u2192 ${upstreamUrl} (stream=${clientWantsStream}, upstreamStream=${streamUpstream}, model=${requestModel ?? "unknown"}, provider=${target.provider})`);
      if (streamUpstream) {
        const streamOk = await tryStreamUpstream(parsed, upstreamUrl, upstreamHeaders, res, log);
        if (streamOk) return;
        log.info("[GuardClaw Proxy] Streaming unavailable, falling back to non-streaming + SSE conversion");
      }
      const upstreamBody = { ...parsed, stream: false };
      const nonStreamController = new AbortController();
      const nonStreamTimeout = setTimeout(() => nonStreamController.abort(), 12e4);
      let upstream;
      try {
        upstream = await fetch(upstreamUrl, {
          method: "POST",
          headers: upstreamHeaders,
          body: JSON.stringify(upstreamBody),
          signal: nonStreamController.signal
        });
      } catch (fetchErr) {
        clearTimeout(nonStreamTimeout);
        const msg = fetchErr instanceof Error && fetchErr.name === "AbortError" ? "Upstream request timed out (120s)" : String(fetchErr);
        log.error(`[GuardClaw Proxy] Upstream fetch failed: ${msg}`);
        res.writeHead(504, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { message: msg, type: "proxy_timeout" } }));
        return;
      }
      clearTimeout(nonStreamTimeout);
      const responseText = await upstream.text();
      log.info(`[GuardClaw Proxy] Upstream responded: status=${upstream.status} ok=${upstream.ok} bodyLen=${responseText.length}`);
      if (!responseText.trim()) {
        log.error(`[GuardClaw Proxy] Upstream returned empty body (status=${upstream.status})`);
        res.writeHead(502, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { message: "Upstream returned empty response", type: "proxy_error" } }));
        return;
      }
      if (clientWantsStream) {
        let responseJson;
        try {
          responseJson = JSON.parse(responseText);
        } catch {
          log.error(`[GuardClaw Proxy] Failed to parse upstream response: ${responseText.slice(0, 200)}`);
          res.writeHead(502, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: { message: "Invalid JSON from upstream", type: "proxy_error" } }));
          return;
        }
        if (upstream.ok) {
          const ssePayload = completionToSSE(responseJson);
          res.writeHead(200, {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive"
          });
          res.end(ssePayload);
        } else {
          res.writeHead(upstream.status, { "Content-Type": "application/json" });
          res.end(JSON.stringify(responseJson));
        }
      } else {
        const contentType = upstream.headers.get("content-type") ?? "application/json";
        res.writeHead(upstream.status, { "Content-Type": contentType });
        res.end(responseText);
      }
    } catch (err) {
      log.error(`[GuardClaw Proxy] Request failed: ${String(err)}`);
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
      }
      if (!res.writableEnded) {
        res.end(JSON.stringify({
          error: {
            message: `GuardClaw proxy error: ${String(err)}`,
            type: "proxy_error"
          }
        }));
      }
    }
  });
  server.on("error", (err) => {
    log.error(`[GuardClaw Proxy] Server error: ${String(err)}`);
  });
  return new Promise((resolve2, reject) => {
    server.listen(port, "127.0.0.1", () => {
      resolve2({
        baseUrl: `http://127.0.0.1:${port}`,
        port,
        close: () => new Promise((r) => {
          server.close(() => r());
          setTimeout(() => r(), 2e3);
        })
      });
    });
    server.on("error", reject);
  });
}

// src/router-pipeline.ts
var RouterPipeline = class {
  routers = /* @__PURE__ */ new Map();
  pipelineConfig = {};
  routerConfigs = /* @__PURE__ */ new Map();
  logger;
  constructor(logger) {
    this.logger = logger ?? {
      info: (m) => console.log(m),
      warn: (m) => console.warn(m),
      error: (m) => console.error(m)
    };
  }
  /**
   * Register a router instance. Overwrites if same id exists.
   */
  register(router, registration) {
    this.routers.set(router.id, router);
    if (registration) {
      this.routerConfigs.set(router.id, registration);
    }
    this.logger.info(`[RouterPipeline] Registered router: ${router.id}`);
  }
  /**
   * Load a custom router from a module path.
   */
  async loadCustomRouter(id, modulePath, registration) {
    try {
      const mod = await import(modulePath);
      const router = mod.default ?? mod;
      if (!router.detect || typeof router.detect !== "function") {
        this.logger.error(`[RouterPipeline] Custom router "${id}" from ${modulePath} does not export a valid detect() function`);
        return;
      }
      router.id = id;
      this.register(router, registration);
    } catch (err) {
      this.logger.error(`[RouterPipeline] Failed to load custom router "${id}" from ${modulePath}: ${String(err)}`);
    }
  }
  /**
   * Configure the pipeline from the plugin config.
   */
  configure(config) {
    if (config.routers) {
      for (const [id, reg] of Object.entries(config.routers)) {
        if (reg) this.routerConfigs.set(id, reg);
      }
    }
    if (config.pipeline) {
      this.pipelineConfig = config.pipeline;
    }
  }
  /**
   * Load all custom routers declared in config.
   */
  async loadCustomRouters() {
    for (const [id, reg] of this.routerConfigs) {
      if (reg.type === "custom" && reg.module && !this.routers.has(id)) {
        await this.loadCustomRouter(id, reg.module, reg);
      }
    }
  }
  /**
   * Get the ordered list of router IDs for a checkpoint.
   * Falls back to running all enabled routers if pipeline config is not set.
   */
  getRoutersForCheckpoint(checkpoint) {
    const configured = this.pipelineConfig[checkpoint];
    if (configured && configured.length > 0) {
      return configured;
    }
    return [...this.routers.keys()];
  }
  /**
   * Check if a router is enabled via config.
   */
  isRouterEnabled(id) {
    const reg = this.routerConfigs.get(id);
    return reg?.enabled !== false;
  }
  /**
   * Get the configured weight for a router (default 50).
   */
  getRouterWeight(id) {
    return this.routerConfigs.get(id)?.weight ?? 50;
  }
  /**
   * Run the pipeline for a given checkpoint.
   *
   * Two-phase execution with short-circuit:
   *   Phase 1 — run all "fast" routers (weight >= 50) in parallel.
   *             If any returns S3 (or S2-local) with a non-passthrough action,
   *             skip slow routers.
   *   Phase 2 — run remaining "slow" routers (weight < 50) when Phase 1 was
   *             all S1, or when S2-proxy is the highest level (so token-saver
   *             can still select the best model for the proxied request).
   *
   * This avoids expensive LLM judge calls (token-saver) when rule-based
   * detection already determined the message must stay local (S3 / S2-local),
   * while still allowing cost optimization for S2-proxy requests.
   */
  async run(checkpoint, context, pluginConfig) {
    const routerIds = this.getRoutersForCheckpoint(checkpoint);
    if (routerIds.length === 0) {
      return { level: "S1", action: "passthrough", reason: "No routers configured" };
    }
    const fast = [];
    const slow = [];
    for (const id of routerIds) {
      if (!this.isRouterEnabled(id)) continue;
      const router = this.routers.get(id);
      if (!router) {
        this.logger.warn(`[RouterPipeline] Router "${id}" referenced in pipeline but not registered`);
        continue;
      }
      const weight = this.getRouterWeight(id);
      (weight >= 50 ? fast : slow).push({ id, weight, router });
    }
    if (fast.length === 0 && slow.length === 0) {
      return { level: "S1", action: "passthrough", reason: "No enabled routers" };
    }
    const fastResults = await this.runGroup(fast, context, pluginConfig);
    for (const r of fastResults) {
      this.logger.info(
        `[RouterPipeline] ${r.decision.routerId}: level=${r.decision.level} action=${r.decision.action ?? "passthrough"} ${r.decision.reason ? `reason="${r.decision.reason}"` : ""} ${r.decision.target ? `target=${r.decision.target.provider}/${r.decision.target.model}` : ""}`.trim()
      );
    }
    const mustShortCircuit = fastResults.some((r) => {
      if (r.decision.level === "S1" || r.decision.action === "passthrough") return false;
      if (r.decision.level === "S2" && r.decision.target?.provider === "guardclaw-privacy") return false;
      return true;
    });
    if (mustShortCircuit || slow.length === 0) {
      if (mustShortCircuit && slow.length > 0) {
        this.logger.info(
          `[GuardClaw] [${checkpoint}] Short-circuit: skipping ${slow.map((s) => s.id).join(",")}`
        );
      }
      const merged2 = mergeDecisionsWeighted(fastResults);
      this.logFinalDecision(checkpoint, merged2);
      return merged2;
    }
    const slowResults = await this.runGroup(slow, context, pluginConfig);
    for (const r of slowResults) {
      this.logger.info(
        `[RouterPipeline] ${r.decision.routerId}: level=${r.decision.level} action=${r.decision.action ?? "passthrough"} ${r.decision.reason ? `reason="${r.decision.reason}"` : ""} ${r.decision.target ? `target=${r.decision.target.provider}/${r.decision.target.model}` : ""}`.trim()
      );
    }
    const merged = mergeDecisionsWeighted([...fastResults, ...slowResults]);
    this.logFinalDecision(checkpoint, merged);
    return merged;
  }
  async runGroup(group, context, pluginConfig) {
    const tasks = group.map(({ id, weight, router }) => ({
      id,
      weight,
      promise: router.detect(context, pluginConfig).then((d) => {
        d.routerId = id;
        return d;
      })
    }));
    const settled = await Promise.allSettled(tasks.map((t) => t.promise));
    const results = [];
    for (let i = 0; i < settled.length; i++) {
      const result = settled[i];
      const { id, weight } = tasks[i];
      if (result.status === "fulfilled") {
        const d = result.value;
        const reasonStr = d.reason ? ` (${d.reason})` : "";
        const targetStr = d.target ? ` \u2192 ${d.target.provider}/${d.target.model}` : "";
        this.logger.info(`[GuardClaw] [${context.checkpoint}] ${id}: ${d.level} ${d.action ?? "passthrough"}${targetStr}${reasonStr}`);
        results.push({ decision: d, weight });
      } else {
        this.logger.error(`[RouterPipeline] Router "${id}" failed: ${String(result.reason)}`);
      }
    }
    return results;
  }
  logFinalDecision(checkpoint, d) {
    const targetStr = d.target ? ` \u2192 ${d.target.provider}/${d.target.model}` : "";
    const reasonStr = d.reason ? ` (${d.reason})` : "";
    const log = d.level === "S1" ? this.logger.info : this.logger.warn;
    log.call(this.logger, `[GuardClaw] [${checkpoint}] \u25B6 Final: ${d.level} ${d.action ?? "passthrough"}${targetStr}${reasonStr}`);
  }
  /**
   * Run a single router by ID (for per-router testing).
   */
  async runSingle(id, context, pluginConfig) {
    const router = this.routers.get(id);
    if (!router) return null;
    const decision = await router.detect({ ...context, dryRun: true }, pluginConfig);
    decision.routerId = id;
    return decision;
  }
  /**
   * List all registered router IDs.
   */
  listRouters() {
    return [...this.routers.keys()];
  }
  /**
   * Check if a router is registered.
   */
  hasRouter(id) {
    return this.routers.has(id);
  }
};
var ACTION_PRIORITY = {
  block: 4,
  redirect: 3,
  transform: 2,
  passthrough: 1
};
function mergeDecisionsWeighted(items) {
  if (items.length === 0) {
    return { level: "S1", action: "passthrough", reason: "No decisions" };
  }
  if (items.length === 1) {
    return items[0].decision;
  }
  const levels = items.map((i) => i.decision.level);
  const winningLevel = maxLevel(...levels);
  const atWinningLevel = items.filter((i) => i.decision.level === winningLevel);
  atWinningLevel.sort((a, b) => {
    if (b.weight !== a.weight) return b.weight - a.weight;
    return (ACTION_PRIORITY[b.decision.action ?? "passthrough"] ?? 0) - (ACTION_PRIORITY[a.decision.action ?? "passthrough"] ?? 0);
  });
  let winner = atWinningLevel[0].decision;
  if (winningLevel === "S1" && (winner.action ?? "passthrough") === "passthrough") {
    const redirectCandidate = atWinningLevel.find(
      (i) => (i.decision.action ?? "passthrough") === "redirect" && i.decision.target
    );
    if (redirectCandidate) {
      winner = redirectCandidate.decision;
    }
  }
  if (winningLevel === "S2" && winner.target?.provider === "guardclaw-privacy" && !winner.target.model) {
    const modelHint = items.find(
      (i) => i.decision.level === "S1" && (i.decision.action ?? "passthrough") === "redirect" && i.decision.target?.model
    );
    if (modelHint) {
      winner = {
        ...winner,
        target: { ...winner.target, model: modelHint.decision.target.model },
        reason: [winner.reason, modelHint.decision.reason].filter(Boolean).join("; ")
      };
    }
  }
  const allReasons = items.filter((i) => i.decision.level !== "S1" && i.decision.reason).map((i) => `[${i.decision.routerId ?? "?"}:w${i.weight}] ${i.decision.reason}`);
  const totalWeight = items.reduce((s, i) => s + i.weight, 0);
  const weightedConfidence = totalWeight > 0 ? items.reduce((s, i) => s + (i.decision.confidence ?? 0.5) * i.weight, 0) / totalWeight : 0.5;
  return {
    level: winningLevel,
    action: winner.action ?? "passthrough",
    target: winner.target,
    transformedContent: winner.transformedContent,
    reason: allReasons.length > 0 ? allReasons.join("; ") : winner.reason,
    confidence: weightedConfidence,
    routerId: winner.routerId
  };
}
var globalPipeline = null;
function setGlobalPipeline(pipeline) {
  globalPipeline = pipeline;
}
function getGlobalPipeline() {
  return globalPipeline;
}

// src/hooks.ts
function getPipelineConfig() {
  return { privacy: getLiveConfig() };
}
function shouldUseFullMemoryTrack(sessionKey) {
  if (isActiveLocalRouting(sessionKey)) return true;
  if (isGuardSessionKey(sessionKey)) return true;
  if (isSessionMarkedPrivate(sessionKey)) {
    const policy = getLiveConfig().s2Policy ?? "proxy";
    return policy === "local";
  }
  return false;
}
function isToolAllowlisted(toolName) {
  const allowlist = getLiveConfig().toolAllowlist;
  if (!allowlist || allowlist.length === 0) return false;
  return allowlist.includes(toolName);
}
var _cachedWorkspaceDir;
function registerHooks(api) {
  const privacyCfgInit = getLiveConfig();
  const sessionBaseDir = privacyCfgInit.session?.baseDir;
  const memoryManager = getDefaultMemoryManager();
  memoryManager.initializeDirectories().catch((err) => {
    api.logger.error(`[GuardClaw] Failed to initialize memory directories: ${String(err)}`);
  });
  getDefaultSessionManager(sessionBaseDir);
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
      if (isGuardSessionKey(sessionKey)) {
        const guardCfg = getGuardAgentConfig(privacyConfig);
        if (guardCfg) {
          return { providerOverride: guardCfg.provider, modelOverride: guardCfg.modelName };
        }
        return;
      }
      if (ctx.workspaceDir) _cachedWorkspaceDir = ctx.workspaceDir;
      const msgStr = String(prompt);
      if (shouldSkipMessage(msgStr)) return;
      const rulePreCheck = detectByRules(
        { checkpoint: "onUserMessage", message: msgStr, sessionKey },
        privacyConfig
      );
      if (rulePreCheck.level === "S3") {
        recordDetection(sessionKey, "S3", "onUserMessage", rulePreCheck.reason);
        trackSessionLevel(sessionKey, "S3");
        setActiveLocalRouting(sessionKey);
        stashDetection(sessionKey, {
          level: "S3",
          reason: rulePreCheck.reason,
          originalPrompt: msgStr,
          timestamp: Date.now()
        });
        const guardCfg = getGuardAgentConfig(privacyConfig);
        const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
        const provider = guardCfg?.provider ?? defaultProvider;
        const model = guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "openbmb/minicpm4.1";
        api.logger.info(`[GuardClaw] S3 (rule fast-path) \u2014 routing to ${provider}/${model}`);
        return { providerOverride: provider, modelOverride: model };
      }
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
          agentId: ctx.agentId
        },
        getPipelineConfig()
      );
      recordDetection(sessionKey, decision.level, "onUserMessage", decision.reason);
      api.logger.info(`[GuardClaw] ROUTE: session=${sessionKey} level=${decision.level} action=${decision.action} target=${JSON.stringify(decision.target)} reason=${decision.reason}`);
      if (decision.level === "S1" && decision.action === "passthrough") {
        return;
      }
      if (decision.level === "S3") {
        trackSessionLevel(sessionKey, "S3");
        setActiveLocalRouting(sessionKey);
        stashDetection(sessionKey, {
          level: "S3",
          reason: decision.reason,
          originalPrompt: msgStr,
          timestamp: Date.now()
        });
        if (decision.target) {
          api.logger.info(`[GuardClaw] S3 \u2014 routing to ${decision.target.provider}/${decision.target.model} [${decision.routerId}]`);
          return {
            providerOverride: decision.target.provider,
            ...decision.target.model ? { modelOverride: decision.target.model } : {}
          };
        }
        const guardCfg = getGuardAgentConfig(privacyConfig);
        const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
        api.logger.info(`[GuardClaw] S3 \u2014 routing to ${guardCfg?.provider ?? defaultProvider}/${guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "openbmb/minicpm4.1"} [${decision.routerId}]`);
        return {
          providerOverride: guardCfg?.provider ?? defaultProvider,
          modelOverride: guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "openbmb/minicpm4.1"
        };
      }
      let desensitized;
      if (decision.level === "S2") {
        const result = await desensitizeWithLocalModel(msgStr, privacyConfig, sessionKey);
        if (result.failed) {
          api.logger.warn("[GuardClaw] S2 desensitization failed \u2014 escalating to S3 (local-only) to prevent PII leak");
          trackSessionLevel(sessionKey, "S3");
          setActiveLocalRouting(sessionKey);
          stashDetection(sessionKey, {
            level: "S3",
            reason: `${decision.reason}; desensitization failed \u2014 escalated to S3`,
            originalPrompt: msgStr,
            timestamp: Date.now()
          });
          const guardCfg = getGuardAgentConfig(privacyConfig);
          const fallbackProvider = privacyConfig.localModel?.provider ?? "ollama";
          return {
            providerOverride: guardCfg?.provider ?? fallbackProvider,
            modelOverride: guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "openbmb/minicpm4.1"
          };
        }
        desensitized = result.desensitized;
      }
      stashDetection(sessionKey, {
        level: decision.level,
        reason: decision.reason,
        desensitized,
        originalPrompt: msgStr,
        timestamp: Date.now()
      });
      if (decision.level === "S2" && decision.action === "redirect" && decision.target?.provider !== "guardclaw-privacy") {
        markSessionAsPrivate(sessionKey, decision.level);
        if (decision.target) {
          api.logger.info(`[GuardClaw] S2 \u2014 routing to ${decision.target.provider}/${decision.target.model} [${decision.routerId}]`);
          return {
            providerOverride: decision.target.provider,
            ...decision.target.model ? { modelOverride: decision.target.model } : {}
          };
        }
      }
      if (decision.level === "S2" && decision.target?.provider === "guardclaw-privacy") {
        markSessionAsPrivate(sessionKey, "S2");
        const defaults = api.config.agents?.defaults;
        const primaryModel = defaults?.model?.primary ?? "";
        const defaultProvider = defaults?.provider || primaryModel.split("/")[0] || "openai";
        const providerConfig = api.config.models?.providers?.[defaultProvider];
        if (providerConfig) {
          const pc = providerConfig;
          const providerApi = pc.api ?? void 0;
          const stashTarget = {
            baseUrl: pc.baseUrl ?? resolveDefaultBaseUrl(defaultProvider, providerApi),
            apiKey: pc.apiKey ?? "",
            provider: defaultProvider,
            api: providerApi
          };
          stashOriginalProvider(sessionKey, stashTarget);
        }
        const modelInfo = decision.target.model ? ` (model=${decision.target.model})` : "";
        api.logger.info(`[GuardClaw] S2 \u2014 routing through privacy proxy${modelInfo} [${decision.routerId}]`);
        return {
          providerOverride: "guardclaw-privacy",
          ...decision.target.model ? { modelOverride: decision.target.model } : {}
        };
      }
      if (decision.action === "redirect" && decision.target) {
        api.logger.info(`[GuardClaw] ${decision.level} \u2014 custom route to ${decision.target.provider}/${decision.target.model} [${decision.routerId}]`);
        return {
          providerOverride: decision.target.provider,
          ...decision.target.model ? { modelOverride: decision.target.model } : {}
        };
      }
      if (decision.action === "block") {
        if (decision.level === "S3") {
          trackSessionLevel(sessionKey, "S3");
          setActiveLocalRouting(sessionKey);
        } else {
          markSessionAsPrivate(sessionKey, decision.level);
        }
        const guardCfg = getGuardAgentConfig(privacyConfig);
        const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
        api.logger.warn(`[GuardClaw] ${decision.level} BLOCK \u2014 redirecting to edge model [${decision.routerId}]`);
        return {
          providerOverride: guardCfg?.provider ?? defaultProvider,
          modelOverride: guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "openbmb/minicpm4.1"
        };
      }
      if (decision.action === "transform") {
        if (decision.level === "S3") {
          trackSessionLevel(sessionKey, "S3");
          setActiveLocalRouting(sessionKey);
          stashDetection(sessionKey, {
            level: "S3",
            reason: decision.reason,
            originalPrompt: msgStr,
            timestamp: Date.now()
          });
          const guardCfg = getGuardAgentConfig(privacyConfig);
          const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
          api.logger.info(`[GuardClaw] S3 TRANSFORM \u2014 routing to edge model [${decision.routerId}]`);
          return {
            providerOverride: guardCfg?.provider ?? defaultProvider,
            modelOverride: guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "openbmb/minicpm4.1"
          };
        }
        if (decision.level === "S2") {
          const transformedText = decision.transformedContent ?? desensitized ?? msgStr;
          stashDetection(sessionKey, {
            level: "S2",
            reason: decision.reason,
            desensitized: transformedText,
            originalPrompt: msgStr,
            timestamp: Date.now()
          });
          markSessionAsPrivate(sessionKey, "S2");
          const s2Policy = privacyConfig.s2Policy ?? "proxy";
          if (s2Policy === "local") {
            const guardCfg = getGuardAgentConfig(privacyConfig);
            const defaultProvider2 = privacyConfig.localModel?.provider ?? "ollama";
            api.logger.info(`[GuardClaw] S2 TRANSFORM \u2014 routing to local ${guardCfg?.provider ?? defaultProvider2} [${decision.routerId}]`);
            return {
              providerOverride: guardCfg?.provider ?? defaultProvider2,
              modelOverride: guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "openbmb/minicpm4.1"
            };
          }
          const defaults = api.config.agents?.defaults;
          const primaryModel = defaults?.model?.primary ?? "";
          const defaultProvider = defaults?.provider || primaryModel.split("/")[0] || "openai";
          const providerConfig = api.config.models?.providers?.[defaultProvider];
          if (providerConfig) {
            const pc = providerConfig;
            const providerApi = pc.api ?? void 0;
            stashOriginalProvider(sessionKey, {
              baseUrl: pc.baseUrl ?? resolveDefaultBaseUrl(defaultProvider, providerApi),
              apiKey: pc.apiKey ?? "",
              provider: defaultProvider,
              api: providerApi
            });
          }
          api.logger.info(`[GuardClaw] S2 TRANSFORM \u2014 routing through privacy proxy [${decision.routerId}]`);
          return { providerOverride: "guardclaw-privacy" };
        }
        return;
      }
      return;
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_model_resolve hook: ${String(err)}`);
    }
  });
  api.on("before_prompt_build", async (_event, ctx) => {
    try {
      const sessionKey = ctx.sessionKey ?? "";
      if (!sessionKey) return;
      const pending = getPendingDetection(sessionKey);
      if (!pending || pending.level === "S1") return;
      const privacyConfig = getLiveConfig();
      const sessionCfg = privacyConfig.session ?? {};
      const shouldInject = sessionCfg.injectDualHistory !== false && sessionCfg.isolateGuardHistory !== false;
      const historyLimit = sessionCfg.historyLimit ?? 20;
      if (pending.level === "S3") {
        if (shouldInject) {
          const context = await loadDualTrackContext(sessionKey, ctx.agentId, historyLimit);
          if (context) {
            api.logger.info(`[GuardClaw] Injected dual-track history context for S3 turn`);
            return { prependContext: context };
          }
        }
        return;
      }
      const s2Policy = privacyConfig.s2Policy ?? "proxy";
      if (pending.level === "S2" && s2Policy === "local") {
        if (shouldInject) {
          const context = await loadDualTrackContext(sessionKey, ctx.agentId, historyLimit);
          if (context) {
            api.logger.info(`[GuardClaw] Injected dual-track history context for S2-local turn`);
            return { prependContext: context };
          }
        }
        return;
      }
      if (pending.level === "S2" && pending.desensitized) {
        return {
          prependContext: `${GUARDCLAW_S2_OPEN}
${pending.desensitized}
${GUARDCLAW_S2_CLOSE}`
        };
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_prompt_build hook: ${String(err)}`);
    }
  });
  api.on("before_tool_call", async (event, ctx) => {
    try {
      const { toolName, params } = event;
      const sessionKey = ctx.sessionKey ?? "";
      if (!toolName) return;
      const typedParams = params;
      const privacyConfig = getLiveConfig();
      const baseDir = privacyConfig.session?.baseDir ?? "~/.openclaw";
      if (!isGuardSessionKey(sessionKey) && !isActiveLocalRouting(sessionKey)) {
        const pathValues = extractPathsFromParams(typedParams);
        for (const p of pathValues) {
          if (isProtectedMemoryPath(p, baseDir)) {
            api.logger.warn(`[GuardClaw] BLOCKED: cloud model tried to access protected path: ${p}`);
            return { block: true, blockReason: `GuardClaw: access to full history/memory is restricted for cloud models (${p})` };
          }
        }
      }
      if (toolName === "memory_get" && shouldUseFullMemoryTrack(sessionKey)) {
        const p = String(typedParams.path ?? "");
        if (p === "MEMORY.md" || p === "memory.md") {
          return { params: { ...typedParams, path: "MEMORY-FULL.md" } };
        }
        if (p.startsWith("memory/")) {
          return { params: { ...typedParams, path: p.replace(/^memory\//, "memory-full/") } };
        }
      }
      const isSpawn = toolName === "sessions_spawn";
      const isSend = toolName === "sessions_send";
      if (isSpawn || isSend) {
        const contentField = isSpawn ? String(typedParams?.task ?? "") : String(typedParams?.message ?? "");
        if (contentField.trim()) {
          const ruleResult = detectByRules(
            { checkpoint: "onToolCallProposed", message: contentField, toolName, toolParams: typedParams, sessionKey },
            privacyConfig
          );
          recordDetection(sessionKey, ruleResult.level, "onToolCallProposed", ruleResult.reason);
          if (ruleResult.level === "S3") {
            trackSessionLevel(sessionKey, "S3");
            return { block: true, blockReason: `GuardClaw: ${isSpawn ? "subagent task" : "A2A message"} blocked \u2014 S3 (${ruleResult.reason ?? "sensitive"})` };
          }
          if (ruleResult.level === "S2") {
            markSessionAsPrivate(sessionKey, "S2");
          }
        }
      }
      if (isExecTool(toolName) && !isActiveLocalRouting(sessionKey) && !isGuardSessionKey(sessionKey)) {
        const command = String(typedParams.command ?? typedParams.cmd ?? typedParams.script ?? "");
        if (command) {
          const blocked = isHighRiskExecCommand(command);
          if (blocked) {
            api.logger.warn(`[GuardClaw] BLOCKED high-risk exec command: ${command.slice(0, 80)}`);
            recordDetection(sessionKey, "S3", "onToolCallProposed", `high-risk exec: ${blocked}`);
            trackSessionLevel(sessionKey, "S3");
            return { block: true, blockReason: `GuardClaw: exec command blocked \u2014 likely to output secrets (${blocked}). Use a local model session for this operation.` };
          }
        }
      }
      if (!isActiveLocalRouting(sessionKey) && !isToolAllowlisted(toolName)) {
        const detectors = privacyConfig.checkpoints?.onToolCallProposed ?? ["ruleDetector"];
        const usePipeline = detectors.includes("localModelDetector");
        let level = "S1";
        let reason;
        if (usePipeline) {
          const pipeline = getGlobalPipeline();
          if (pipeline) {
            const decision = await pipeline.run(
              "onToolCallProposed",
              { checkpoint: "onToolCallProposed", toolName, toolParams: typedParams, sessionKey },
              getPipelineConfig()
            );
            level = decision.level;
            reason = decision.reason;
          }
        } else {
          const ruleResult = detectByRules(
            { checkpoint: "onToolCallProposed", toolName, toolParams: typedParams, sessionKey },
            privacyConfig
          );
          level = ruleResult.level;
          reason = ruleResult.reason;
        }
        recordDetection(sessionKey, level, "onToolCallProposed", reason);
        if (level === "S3") {
          trackSessionLevel(sessionKey, "S3");
          return { block: true, blockReason: `GuardClaw: tool "${toolName}" blocked \u2014 S3 (${reason ?? "sensitive"})` };
        }
        if (level === "S2") {
          markSessionAsPrivate(sessionKey, "S2");
        }
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_tool_call hook: ${String(err)}`);
    }
  });
  api.on("tool_result_persist", (event, ctx) => {
    try {
      const sessionKey = ctx.sessionKey ?? "";
      if (!sessionKey) return;
      const msg = event.message;
      if (!msg) return;
      if (ctx.toolName === "write" || ctx.toolName === "write_file") {
        const writePath = String(event.params?.path ?? "");
        if (writePath && isMemoryWritePath(writePath)) {
          const workspaceDir = _cachedWorkspaceDir ?? process.cwd();
          const privacyConfig2 = getLiveConfig();
          syncMemoryWrite(writePath, workspaceDir, privacyConfig2, api.logger, isGuardSessionKey(sessionKey)).catch((err) => {
            api.logger.warn(`[GuardClaw] Memory dual-write sync failed: ${String(err)}`);
          });
        }
      }
      if (ctx.toolName === "memory_search") {
        const filtered = filterMemorySearchResults(msg, shouldUseFullMemoryTrack(sessionKey));
        if (filtered) return { message: filtered };
        return;
      }
      if (isActiveLocalRouting(sessionKey)) {
        const textContent2 = extractMessageText(msg);
        if (textContent2 && textContent2.length >= 10) {
          const sessionManager = getDefaultSessionManager();
          sessionManager.writeToFull(sessionKey, {
            role: "tool",
            content: textContent2,
            timestamp: Date.now(),
            sessionKey
          }).catch(() => {
          });
          const redacted2 = redactSensitiveInfo(textContent2, getLiveConfig().redaction);
          if (redacted2 !== textContent2) {
            api.logger.info(`[GuardClaw] S3 tool result PII-redacted for transcript (tool=${ctx.toolName ?? "unknown"})`);
            sessionManager.writeToClean(sessionKey, {
              role: "tool",
              content: redacted2,
              timestamp: Date.now(),
              sessionKey
            }).catch(() => {
            });
            const modified = replaceMessageText(msg, redacted2);
            if (modified) return { message: modified };
          } else {
            sessionManager.writeToClean(sessionKey, {
              role: "tool",
              content: textContent2,
              timestamp: Date.now(),
              sessionKey
            }).catch(() => {
            });
          }
        }
        return;
      }
      if (ctx.toolName && isToolAllowlisted(ctx.toolName)) return;
      const textContent = extractMessageText(msg);
      if (!textContent || textContent.length < 10) return;
      const privacyConfig = getLiveConfig();
      const wasPrivateBefore = isSessionMarkedPrivate(sessionKey);
      const ruleCheck = detectByRules(
        {
          checkpoint: "onToolCallExecuted",
          toolName: ctx.toolName,
          toolResult: textContent,
          sessionKey
        },
        privacyConfig
      );
      const detectedSensitive = ruleCheck.level === "S3" || ruleCheck.level === "S2";
      const effectiveLevel = ruleCheck.level === "S3" ? "S2" : ruleCheck.level;
      if (detectedSensitive) {
        trackSessionLevel(sessionKey, ruleCheck.level);
        markSessionAsPrivate(sessionKey, effectiveLevel);
        recordDetection(sessionKey, ruleCheck.level, "onToolCallExecuted", ruleCheck.reason);
        if (ruleCheck.level === "S3") {
          api.logger.warn(
            `[GuardClaw] S3 detected in tool result AFTER cloud model already active \u2014 degrading to S2 (PII redaction). tool=${ctx.toolName ?? "unknown"}, reason=${ruleCheck.reason ?? "rule-match"}`
          );
        }
      }
      const redacted = redactSensitiveInfo(textContent, getLiveConfig().redaction);
      const wasRedacted = redacted !== textContent;
      if (detectedSensitive || wasRedacted || wasPrivateBefore) {
        const sessionManager = getDefaultSessionManager();
        sessionManager.writeToFull(sessionKey, {
          role: "tool",
          content: textContent,
          timestamp: Date.now(),
          sessionKey
        }).catch(() => {
        });
        sessionManager.writeToClean(sessionKey, {
          role: "tool",
          content: wasRedacted ? redacted : textContent,
          timestamp: Date.now(),
          sessionKey
        }).catch(() => {
        });
      }
      if (wasRedacted) {
        if (!detectedSensitive) markSessionAsPrivate(sessionKey, "S2");
        api.logger.info(`[GuardClaw] PII-redacted tool result for transcript (tool=${ctx.toolName ?? "unknown"})`);
        const modified = replaceMessageText(msg, redacted);
        if (modified) return { message: modified };
      }
      if (privacyConfig.localModel?.enabled && ruleCheck.level !== "S3") {
        const llmResult = syncDetectByLocalModel(
          { checkpoint: "onToolCallExecuted", toolName: ctx.toolName, toolResult: textContent, sessionKey },
          privacyConfig
        );
        if (llmResult.level !== "S1" && llmResult.levelNumeric > ruleCheck.levelNumeric) {
          const llmEffective = llmResult.level === "S3" ? "S2" : llmResult.level;
          trackSessionLevel(sessionKey, llmResult.level);
          if (!detectedSensitive) {
            markSessionAsPrivate(sessionKey, llmEffective);
          }
          recordDetection(sessionKey, llmResult.level, "onToolCallExecuted", llmResult.reason);
          if (llmResult.level === "S3") {
            api.logger.warn(
              `[GuardClaw] LLM elevated tool result to S3 \u2014 PII redacted before reaching cloud model. tool=${ctx.toolName ?? "unknown"}, reason=${llmResult.reason ?? "semantic"}`
            );
          } else {
            api.logger.info(`[GuardClaw] LLM elevated tool result to ${llmResult.level} (tool=${ctx.toolName ?? "unknown"}, reason=${llmResult.reason ?? "semantic"})`);
          }
          if (!detectedSensitive && !wasRedacted && !wasPrivateBefore) {
            const sessionManager = getDefaultSessionManager();
            const ts = Date.now();
            sessionManager.writeToFull(sessionKey, { role: "tool", content: textContent, timestamp: ts, sessionKey }).catch(() => {
            });
            sessionManager.writeToClean(sessionKey, { role: "tool", content: redacted, timestamp: ts, sessionKey }).catch(() => {
            });
          }
          if (llmResult.level === "S3") {
            const s3Redacted = wasRedacted ? redacted : redactSensitiveInfo(textContent, getLiveConfig().redaction);
            const modified = replaceMessageText(msg, s3Redacted);
            if (modified) return { message: modified };
          }
        }
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in tool_result_persist hook: ${String(err)}`);
    }
  });
  api.on("before_message_write", (event, ctx) => {
    try {
      const sessionKey = ctx.sessionKey ?? "";
      if (!sessionKey) return;
      const msg = event.message;
      if (!msg) return;
      const role = msg.role ?? "";
      const pending = getPendingDetection(sessionKey);
      const needsDualHistory = isSessionMarkedPrivate(sessionKey) || pending?.level === "S3" || isActiveLocalRouting(sessionKey);
      if (needsDualHistory && role !== "tool") {
        const sessionManager = getDefaultSessionManager();
        const msgText = extractMessageText(msg);
        const ts = Date.now();
        if (role === "user" && pending && pending.level !== "S1") {
          const original = pending.originalPrompt ?? msgText;
          sessionManager.writeToFull(sessionKey, {
            role: "user",
            content: original,
            timestamp: ts,
            sessionKey
          }).catch((err) => {
            console.error("[GuardClaw] Failed to persist user message to full history:", err);
          });
          const cleanContent = pending.level === "S3" ? buildMainSessionPlaceholder("S3") : pending.desensitized ?? msgText;
          sessionManager.writeToClean(sessionKey, {
            role: "user",
            content: cleanContent,
            timestamp: ts,
            sessionKey
          }).catch((err) => {
            console.error("[GuardClaw] Failed to persist user message to clean history:", err);
          });
        } else if (msgText) {
          if (role === "assistant" && isActiveLocalRouting(sessionKey)) {
            const redacted = redactSensitiveInfo(msgText, getLiveConfig().redaction);
            sessionManager.writeToFull(sessionKey, {
              role: "assistant",
              content: msgText,
              timestamp: ts,
              sessionKey
            }).catch((err) => {
              console.error("[GuardClaw] Failed to persist assistant message to full history:", err);
            });
            sessionManager.writeToClean(sessionKey, {
              role: "assistant",
              content: redacted,
              timestamp: ts,
              sessionKey
            }).catch((err) => {
              console.error("[GuardClaw] Failed to persist assistant message to clean history:", err);
            });
          } else {
            sessionManager.persistMessage(sessionKey, {
              role: role || "assistant",
              content: msgText,
              timestamp: ts,
              sessionKey
            }).catch((err) => {
              console.error("[GuardClaw] Failed to persist message to dual history:", err);
            });
          }
        }
      }
      if (role === "assistant" && isActiveLocalRouting(sessionKey)) {
        const assistantText = extractMessageText(msg);
        if (assistantText && assistantText.length >= 10) {
          const redacted = redactSensitiveInfo(assistantText, getLiveConfig().redaction);
          if (redacted !== assistantText) {
            api.logger.info("[GuardClaw] PII-redacted local model response before transcript write");
            return { message: { ...msg, content: [{ type: "text", text: redacted }] } };
          }
        }
      }
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
  api.on("session_end", async (event, ctx) => {
    try {
      const sessionKey = event.sessionKey ?? ctx.sessionKey;
      if (!sessionKey) return;
      const wasPrivate = isSessionMarkedPrivate(sessionKey);
      api.logger.info(`[GuardClaw] ${wasPrivate ? "private" : "cloud"} session ${sessionKey} ended. Syncing memory\u2026`);
      const memMgr = getDefaultMemoryManager();
      const privacyConfig = getLiveConfig();
      await memMgr.syncAllMemoryToClean(privacyConfig);
      clearSessionState(sessionKey);
      const collector = getGlobalCollector();
      if (collector) await collector.flush();
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in session_end hook: ${String(err)}`);
    }
  });
  api.on("after_compaction", async (_event, ctx) => {
    try {
      if (ctx.workspaceDir) _cachedWorkspaceDir = ctx.workspaceDir;
      const memMgr = getDefaultMemoryManager();
      const privacyConfig = getLiveConfig();
      await memMgr.syncAllMemoryToClean(privacyConfig);
      api.logger.info("[GuardClaw] Memory synced after compaction");
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in after_compaction hook: ${String(err)}`);
    }
  });
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
        usage: event.usage
      });
      const liveConfig = getLiveConfig();
      const origin = provider === "guardclaw-privacy" ? "cloud" : isLocalProvider(provider, liveConfig.localProviders) ? "local" : "cloud";
      const reason = provider === "guardclaw-privacy" ? "guardclaw_proxy_to_cloud" : origin === "local" ? "local_provider" : "provider_not_local";
      recordFinalReply({
        sessionKey,
        provider,
        model,
        usage: event.usage,
        extraLocalProviders: liveConfig.localProviders,
        originHint: origin,
        reasonHint: reason
      });
      finalizeLoop(sessionKey);
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in llm_output hook: ${String(err)}`);
    }
  });
  api.on("before_reset", async (_event, ctx) => {
    try {
      if (ctx.workspaceDir) _cachedWorkspaceDir = ctx.workspaceDir;
      const memMgr = getDefaultMemoryManager();
      const privacyConfig = getLiveConfig();
      await memMgr.syncAllMemoryToClean(privacyConfig);
      api.logger.info("[GuardClaw] Memory synced before reset");
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_reset hook: ${String(err)}`);
    }
  });
  api.on("message_sending", async (event, ctx) => {
    try {
      const { content } = event;
      if (!content?.trim()) return;
      const privacyConfig = getLiveConfig();
      if (!privacyConfig.enabled) return;
      const pipeline = getGlobalPipeline();
      if (!pipeline) return;
      const sessionKey = ctx.sessionKey ?? "";
      const decision = await pipeline.run(
        "onUserMessage",
        { checkpoint: "onUserMessage", message: content, sessionKey },
        getPipelineConfig()
      );
      if (decision.level === "S3" || decision.action === "block") {
        api.logger.warn("[GuardClaw] BLOCKED outbound message: S3/block detected");
        return { cancel: true };
      }
      if (decision.level === "S2") {
        const desenResult = await desensitizeWithLocalModel(content, privacyConfig, ctx.sessionKey);
        if (desenResult.failed) {
          api.logger.warn("[GuardClaw] S2 desensitization failed \u2014 cancelling outbound message to prevent PII leak");
          return { cancel: true };
        }
        return { content: desenResult.desensitized };
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in message_sending hook: ${String(err)}`);
    }
  });
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
        getPipelineConfig()
      );
      if (decision.level === "S3" || decision.action === "block") {
        const guardCfg = getGuardAgentConfig(privacyConfig);
        const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
        const provider = guardCfg?.provider ?? defaultProvider;
        const model = guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "openbmb/minicpm4.1";
        api.logger.info(`[GuardClaw] Subagent ${decision.level} \u2014 routing to ${provider}/${model}`);
        return {
          providerOverride: provider,
          modelOverride: model
        };
      }
      if (decision.level === "S2") {
        const privacyCfg = getLiveConfig();
        const desenResult = await desensitizeWithLocalModel(prompt, privacyCfg, sessionKey);
        if (desenResult.failed) {
          const guardCfg = getGuardAgentConfig(privacyCfg);
          const fallbackProvider = privacyCfg.localModel?.provider ?? "ollama";
          const provider = guardCfg?.provider ?? fallbackProvider;
          const model = guardCfg?.modelName ?? privacyCfg.localModel?.model ?? "openbmb/minicpm4.1";
          api.logger.warn(`[GuardClaw] Subagent S2 desensitization failed \u2014 routing to local ${provider}/${model}`);
          return { providerOverride: provider, modelOverride: model };
        }
        api.logger.info("[GuardClaw] Subagent S2 \u2014 prompt desensitized before forwarding");
        return { prompt: desenResult.desensitized };
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_agent_start hook: ${String(err)}`);
    }
  });
  api.on("message_received", async (event, _ctx) => {
    try {
      const privacyConfig = getLiveConfig();
      if (!privacyConfig.enabled) return;
      api.logger.info?.(`[GuardClaw] Message received from ${event.from ?? "unknown"}`);
    } catch {
    }
  });
  api.logger.info("[GuardClaw] All hooks registered (13 hooks, pipeline-driven)");
}
var EXEC_TOOL_NAMES = /* @__PURE__ */ new Set(["exec", "shell", "system.run", "run_command", "execute", "bash", "terminal"]);
function isExecTool(toolName) {
  return EXEC_TOOL_NAMES.has(toolName) || toolName.startsWith("exec") || toolName.includes("shell");
}
var HIGH_RISK_EXEC_PATTERNS = [
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
  { pattern: /\bwget\b.*(?:--password|--http-password|--ftp-password)/i, reason: "wget with inline password" }
];
function isHighRiskExecCommand(command) {
  const normalized = command.trim();
  for (const { pattern, reason } of HIGH_RISK_EXEC_PATTERNS) {
    if (pattern.test(normalized)) return reason;
  }
  return null;
}
function shouldSkipMessage(msg) {
  if (msg.includes("[REDACTED:") || msg.startsWith("[SYSTEM]")) return true;
  if (/^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}/.test(msg)) return true;
  return false;
}
function extractMessageText(msg) {
  if (typeof msg === "string") return msg;
  if (!msg || typeof msg !== "object") return "";
  const m = msg;
  if (typeof m.content === "string") return m.content;
  if (Array.isArray(m.content)) {
    return m.content.map((part) => {
      if (typeof part === "string") return part;
      if (part && typeof part === "object" && typeof part.text === "string") {
        return part.text;
      }
      return "";
    }).filter(Boolean).join("\n");
  }
  return "";
}
function replaceMessageText(msg, newText) {
  if (typeof msg === "string") return newText;
  if (!msg || typeof msg !== "object") return null;
  const m = { ...msg };
  if (typeof m.content === "string") {
    return { ...m, content: newText };
  }
  if (Array.isArray(m.content)) {
    let textReplaced = false;
    const newContent = [];
    for (const part of m.content) {
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
async function loadDualTrackContext(sessionKey, agentId, limit) {
  try {
    const mgr = getDefaultSessionManager();
    const delta = await mgr.loadHistoryDelta(sessionKey, agentId ?? "main", limit);
    if (delta.length === 0) return null;
    return DualSessionManager.formatAsContext(delta);
  } catch {
    return null;
  }
}
var MEMORY_WRITE_PATTERNS = [
  /^MEMORY\.md$/,
  /^memory\.md$/,
  /^memory\//
];
function isMemoryWritePath(writePath) {
  const rel = writePath.replace(/^\.\//, "");
  return MEMORY_WRITE_PATTERNS.some((p) => p.test(rel));
}
async function syncMemoryWrite(writePath, workspaceDir, privacyConfig, logger, isGuardSession = false) {
  const rel = writePath.replace(/^\.\//, "");
  const absPath = path3.isAbsolute(writePath) ? writePath : path3.resolve(workspaceDir, rel);
  let content;
  try {
    content = await fs3.promises.readFile(absPath, "utf-8");
  } catch {
    return;
  }
  if (!content.trim()) return;
  let fullRelPath;
  if (rel === "MEMORY.md" || rel === "memory.md") {
    fullRelPath = "MEMORY-FULL.md";
  } else if (rel.startsWith("memory/")) {
    fullRelPath = rel.replace(/^memory\//, "memory-full/");
  } else {
    return;
  }
  const fullAbsPath = path3.resolve(workspaceDir, fullRelPath);
  await fs3.promises.mkdir(path3.dirname(fullAbsPath), { recursive: true });
  const fullContent = isGuardSession ? `${GUARD_SECTION_BEGIN}
${content}
${GUARD_SECTION_END}` : content;
  await fs3.promises.writeFile(fullAbsPath, fullContent, "utf-8");
  const memMgr = getDefaultMemoryManager();
  const redacted = await memMgr.redactContentPublic(content, privacyConfig);
  if (redacted !== content) {
    await fs3.promises.writeFile(absPath, redacted, "utf-8");
    logger.info(`[GuardClaw] Memory dual-write: ${rel} \u2192 ${fullRelPath} (redacted clean copy)`);
  } else {
    logger.info(`[GuardClaw] Memory dual-write: ${rel} \u2192 ${fullRelPath} (no PII found)`);
  }
}
function filterMemorySearchResults(msg, useFullTrack) {
  if (!msg || typeof msg !== "object") return null;
  const m = msg;
  const textContent = extractMessageText(msg);
  if (!textContent) return null;
  try {
    const parsed = JSON.parse(textContent);
    if (!parsed || typeof parsed !== "object") return null;
    const results = parsed.results;
    if (!Array.isArray(results)) return null;
    const filtered = results.filter((r) => {
      if (!r || typeof r !== "object") return true;
      const rPath = String(r.path ?? "");
      if (useFullTrack) {
        if (rPath === "MEMORY.md" || rPath === "memory.md" || rPath.startsWith("memory/")) {
          return false;
        }
      } else {
        if (rPath === "MEMORY-FULL.md" || rPath.startsWith("memory-full/")) {
          return false;
        }
      }
      return true;
    });
    if (filtered.length === results.length) return null;
    const newParsed = { ...parsed, results: filtered };
    const newText = JSON.stringify(newParsed);
    return replaceMessageText(msg, newText);
  } catch {
    return null;
  }
}

// src/detector.ts
async function detectSensitivityLevel(context, pluginConfig, resolvedConfig) {
  const privacyConfig = resolvedConfig ?? mergeWithDefaults(
    pluginConfig?.privacy ?? {},
    defaultPrivacyConfig
  );
  if (privacyConfig.enabled === false && !context.dryRun) {
    return {
      level: "S1",
      levelNumeric: 1,
      reason: "Privacy detection disabled",
      detectorType: "ruleDetector",
      confidence: 1
    };
  }
  const detectors = getDetectorsForCheckpoint(context.checkpoint, privacyConfig);
  if (detectors.length === 0) {
    return {
      level: "S1",
      levelNumeric: 1,
      reason: "No detectors configured",
      detectorType: "ruleDetector",
      confidence: 1
    };
  }
  const results = await runDetectors(detectors, context, privacyConfig);
  return mergeDetectionResults(results);
}
function getDetectorsForCheckpoint(checkpoint, config) {
  const checkpoints = config.checkpoints ?? {};
  switch (checkpoint) {
    case "onUserMessage":
      return checkpoints.onUserMessage ?? ["ruleDetector", "localModelDetector"];
    case "onToolCallProposed":
      return checkpoints.onToolCallProposed ?? ["ruleDetector"];
    case "onToolCallExecuted":
      return checkpoints.onToolCallExecuted ?? ["ruleDetector"];
    default:
      return ["ruleDetector"];
  }
}
async function runDetectors(detectors, context, config) {
  const results = [];
  for (const detector of detectors) {
    try {
      let result;
      switch (detector) {
        case "ruleDetector":
          result = detectByRules(context, config);
          break;
        case "localModelDetector":
          result = await detectByLocalModel(context, config);
          break;
        default:
          console.warn(`[GuardClaw] Unknown detector type: ${detector}`);
          continue;
      }
      results.push(result);
      if (result.level === "S3") break;
    } catch (err) {
      console.error(`[GuardClaw] Detector ${detector} failed:`, err);
    }
  }
  return results;
}
function mergeDetectionResults(results) {
  if (results.length === 0) {
    return {
      level: "S1",
      levelNumeric: 1,
      reason: "No detection results",
      detectorType: "ruleDetector",
      confidence: 0
    };
  }
  if (results.length === 1) {
    return results[0];
  }
  const levels = results.map((r) => r.level);
  const finalLevel = maxLevel(...levels);
  const relevantResults = results.filter((r) => r.level === finalLevel);
  const reasons = relevantResults.map((r) => r.reason).filter((r) => Boolean(r));
  const confidences = results.map((r) => r.confidence ?? 0.5);
  const avgConfidence = confidences.reduce((a, b) => a + b, 0) / confidences.length;
  const primaryDetector = relevantResults[0]?.detectorType ?? "ruleDetector";
  return {
    level: finalLevel,
    levelNumeric: results.find((r) => r.level === finalLevel)?.levelNumeric ?? 1,
    reason: reasons.length > 0 ? reasons.join("; ") : void 0,
    detectorType: primaryDetector,
    confidence: avgConfidence
  };
}
function mergeWithDefaults(userConfig, defaults) {
  return {
    enabled: userConfig.enabled ?? defaults.enabled,
    checkpoints: {
      onUserMessage: userConfig.checkpoints?.onUserMessage ?? defaults.checkpoints?.onUserMessage,
      onToolCallProposed: userConfig.checkpoints?.onToolCallProposed ?? defaults.checkpoints?.onToolCallProposed,
      onToolCallExecuted: userConfig.checkpoints?.onToolCallExecuted ?? defaults.checkpoints?.onToolCallExecuted
    },
    rules: {
      keywords: {
        S2: userConfig.rules?.keywords?.S2 ?? defaults.rules?.keywords?.S2,
        S3: userConfig.rules?.keywords?.S3 ?? defaults.rules?.keywords?.S3
      },
      patterns: {
        S2: userConfig.rules?.patterns?.S2 ?? defaults.rules?.patterns?.S2,
        S3: userConfig.rules?.patterns?.S3 ?? defaults.rules?.patterns?.S3
      },
      tools: {
        S2: {
          tools: userConfig.rules?.tools?.S2?.tools ?? defaults.rules?.tools?.S2?.tools,
          paths: userConfig.rules?.tools?.S2?.paths ?? defaults.rules?.tools?.S2?.paths
        },
        S3: {
          tools: userConfig.rules?.tools?.S3?.tools ?? defaults.rules?.tools?.S3?.tools,
          paths: userConfig.rules?.tools?.S3?.paths ?? defaults.rules?.tools?.S3?.paths
        }
      }
    },
    localModel: {
      enabled: userConfig.localModel?.enabled ?? defaults.localModel?.enabled,
      type: userConfig.localModel?.type ?? defaults.localModel?.type,
      provider: userConfig.localModel?.provider ?? defaults.localModel?.provider,
      model: userConfig.localModel?.model ?? defaults.localModel?.model,
      endpoint: userConfig.localModel?.endpoint ?? defaults.localModel?.endpoint,
      apiKey: userConfig.localModel?.apiKey ?? defaults.localModel?.apiKey,
      module: userConfig.localModel?.module ?? defaults.localModel?.module
    },
    guardAgent: {
      id: userConfig.guardAgent?.id ?? defaults.guardAgent?.id,
      workspace: userConfig.guardAgent?.workspace ?? defaults.guardAgent?.workspace,
      model: userConfig.guardAgent?.model ?? defaults.guardAgent?.model
    },
    session: {
      isolateGuardHistory: userConfig.session?.isolateGuardHistory ?? defaults.session?.isolateGuardHistory,
      baseDir: userConfig.session?.baseDir ?? defaults.session?.baseDir,
      injectDualHistory: userConfig.session?.injectDualHistory ?? defaults.session?.injectDualHistory,
      historyLimit: userConfig.session?.historyLimit ?? defaults.session?.historyLimit
    }
  };
}

// src/routers/privacy.ts
function detectionToDecision(level, reason, privacyConfig) {
  if (level === "S1") {
    return { level: "S1", action: "passthrough", reason };
  }
  if (level === "S3") {
    const guardCfg = getGuardAgentConfig(privacyConfig);
    const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
    return {
      level: "S3",
      action: "redirect",
      target: {
        provider: guardCfg?.provider ?? defaultProvider,
        model: guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "openbmb/minicpm4.1"
      },
      reason
    };
  }
  const s2Policy = privacyConfig.s2Policy ?? "proxy";
  if (s2Policy === "local") {
    const guardCfg = getGuardAgentConfig(privacyConfig);
    const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
    return {
      level: "S2",
      action: "redirect",
      target: {
        provider: guardCfg?.provider ?? defaultProvider,
        model: guardCfg?.modelName ?? privacyConfig.localModel?.model ?? "openbmb/minicpm4.1"
      },
      reason
    };
  }
  return {
    level: "S2",
    action: "redirect",
    target: { provider: "guardclaw-privacy", model: "" },
    reason
  };
}
function getPrivacyConfig(pluginConfig) {
  const userConfig = pluginConfig?.privacy ?? {};
  return {
    ...defaultPrivacyConfig,
    ...userConfig,
    checkpoints: { ...defaultPrivacyConfig.checkpoints, ...userConfig.checkpoints },
    rules: {
      keywords: { ...defaultPrivacyConfig.rules.keywords, ...userConfig.rules?.keywords },
      patterns: { ...defaultPrivacyConfig.rules.patterns, ...userConfig.rules?.patterns },
      tools: {
        S2: { ...defaultPrivacyConfig.rules.tools.S2, ...userConfig.rules?.tools?.S2 },
        S3: { ...defaultPrivacyConfig.rules.tools.S3, ...userConfig.rules?.tools?.S3 }
      }
    },
    localModel: { ...defaultPrivacyConfig.localModel, ...userConfig.localModel },
    guardAgent: { ...defaultPrivacyConfig.guardAgent, ...userConfig.guardAgent },
    session: { ...defaultPrivacyConfig.session, ...userConfig.session }
  };
}
var privacyRouter = {
  id: "privacy",
  async detect(context, pluginConfig) {
    const privacyConfig = getPrivacyConfig(pluginConfig);
    if (privacyConfig.enabled === false && !context.dryRun) {
      return { level: "S1", action: "passthrough", reason: "Privacy detection disabled" };
    }
    const result = await detectSensitivityLevel(context, pluginConfig, privacyConfig);
    return detectionToDecision(result.level, result.reason, privacyConfig);
  }
};

// src/routers/token-saver.ts
import { createHash } from "crypto";
var DEFAULT_CONFIG = {
  enabled: false,
  judgeEndpoint: "http://localhost:11434",
  judgeModel: "openbmb/minicpm4.1",
  judgeProviderType: "openai-compatible",
  tiers: {
    SIMPLE: { provider: "openai", model: "gpt-4o-mini" },
    MEDIUM: { provider: "openai", model: "gpt-4o" },
    COMPLEX: { provider: "anthropic", model: "claude-sonnet-4.6" },
    REASONING: { provider: "openai", model: "o4-mini" }
  },
  cacheTtlMs: 3e5
};
var DEFAULT_JUDGE_PROMPT = `You are a task complexity classifier. Classify the user's task into exactly one tier.

SIMPLE = lookup, translation, formatting, yes/no, definition, greeting, simple file search, reading a single file, listing items
MEDIUM = code generation, data analysis, moderate writing, single-file edits, summarization, debugging a specific function
COMPLEX = system design, multi-file refactoring, architecture decisions, large code generation, project-wide changes
REASONING = math proof, formal logic, step-by-step derivation, deep analysis with constraints, algorithm correctness proof

Rules:
- When unsure, pick the LOWER tier (save tokens).
- Short prompts (< 20 words) with no technical depth \u2192 SIMPLE.
- Presence of code fences alone does not mean COMPLEX \u2014 a short snippet for review is MEDIUM.

Output ONLY a JSON object, nothing else: {"tier":"SIMPLE|MEDIUM|COMPLEX|REASONING"}`;
var classificationCache = /* @__PURE__ */ new Map();
var CACHE_CLEANUP_INTERVAL_MS = 6e4;
var CACHE_MAX_AGE_MS = 6e5;
var cleanupTimer = null;
function startCacheCleanup() {
  if (cleanupTimer) return;
  cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of classificationCache) {
      if (now - v.ts > CACHE_MAX_AGE_MS) classificationCache.delete(k);
    }
  }, CACHE_CLEANUP_INTERVAL_MS);
  if (cleanupTimer && typeof cleanupTimer === "object" && "unref" in cleanupTimer) {
    cleanupTimer.unref();
  }
}
function hashPrompt(prompt) {
  return createHash("sha256").update(prompt).digest("hex").slice(0, 16);
}
var VALID_TIERS = /* @__PURE__ */ new Set(["SIMPLE", "MEDIUM", "COMPLEX", "REASONING"]);
function parseTier(response) {
  try {
    const cleaned = response.replace(/<think>[\s\S]*?<\/think>/g, "").trim();
    const match = cleaned.match(/\{[\s\S]*?"tier"\s*:\s*"([A-Z]+)"[\s\S]*?\}/);
    if (match) {
      const tier = match[1];
      if (VALID_TIERS.has(tier)) return tier;
    }
  } catch {
  }
  return "MEDIUM";
}
function buildDecision(tier, config) {
  const target = config.tiers[tier];
  if (!target) {
    return { level: "S1", action: "passthrough", reason: `no model mapping for tier ${tier}` };
  }
  return {
    level: "S1",
    action: "redirect",
    target: { provider: target.provider, model: target.model },
    reason: `tier=${tier}`,
    confidence: 0.8
  };
}
function resolveConfig(pluginConfig) {
  const routers = pluginConfig?.privacy?.routers;
  const tsConfig = routers?.["token-saver"];
  const options = tsConfig?.options ?? {};
  const privacyLocalModel = pluginConfig?.privacy?.localModel;
  return {
    enabled: tsConfig?.enabled ?? DEFAULT_CONFIG.enabled,
    judgeEndpoint: options.judgeEndpoint ?? privacyLocalModel?.endpoint ?? DEFAULT_CONFIG.judgeEndpoint,
    judgeModel: options.judgeModel ?? privacyLocalModel?.model ?? DEFAULT_CONFIG.judgeModel,
    judgeProviderType: options.judgeProviderType ?? privacyLocalModel?.type ?? DEFAULT_CONFIG.judgeProviderType,
    judgeCustomModule: options.judgeCustomModule ?? privacyLocalModel?.module,
    judgeApiKey: options.judgeApiKey ?? privacyLocalModel?.apiKey,
    tiers: {
      ...DEFAULT_CONFIG.tiers,
      ...options.tiers ?? {}
    },
    cacheTtlMs: options.cacheTtlMs ?? DEFAULT_CONFIG.cacheTtlMs
  };
}
var tokenSaverRouter = {
  id: "token-saver",
  async detect(context, pluginConfig) {
    const config = resolveConfig(pluginConfig);
    if (!config.enabled && !context.dryRun) {
      return { level: "S1", action: "passthrough" };
    }
    const isSubagent = context.sessionKey?.includes(":subagent:") ?? false;
    if (isSubagent) {
      return { level: "S1", action: "passthrough", reason: "subagent \u2014 skipped" };
    }
    const prompt = context.message ?? "";
    if (!prompt.trim()) {
      return { level: "S1", action: "passthrough" };
    }
    startCacheCleanup();
    const cacheKey = hashPrompt(prompt);
    const cached = classificationCache.get(cacheKey);
    if (cached && Date.now() - cached.ts < config.cacheTtlMs) {
      return buildDecision(cached.tier, config);
    }
    try {
      const judgeSystemPrompt = loadPrompt("token-saver-judge", DEFAULT_JUDGE_PROMPT);
      const result = await callChatCompletion(
        config.judgeEndpoint,
        config.judgeModel,
        [
          { role: "system", content: judgeSystemPrompt },
          { role: "user", content: prompt }
        ],
        {
          temperature: 0,
          maxTokens: 1024,
          providerType: config.judgeProviderType,
          customModule: config.judgeCustomModule,
          apiKey: config.judgeApiKey
        }
      );
      if (result.usage) {
        const collector = getGlobalCollector();
        collector?.record({
          sessionKey: context.sessionKey ?? "",
          provider: "edge",
          model: config.judgeModel,
          source: "router",
          usage: result.usage
        });
      }
      const tier = parseTier(result.text);
      classificationCache.set(cacheKey, { tier, ts: Date.now() });
      return buildDecision(tier, config);
    } catch (err) {
      console.error(`[GuardClaw] [TokenSaver] judge call failed:`, err);
      return { level: "S1", action: "passthrough", reason: "judge call failed \u2014 passthrough" };
    }
  }
};

// src/stats-dashboard.ts
import { readFileSync as readFileSync2, writeFileSync as writeFileSync2, mkdirSync as mkdirSync2 } from "fs";
import { join as join4 } from "path";

// src/presets.ts
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { join as join3 } from "path";
var BUILTIN_PRESETS = [
  {
    id: "vllm-qwen35",
    name: "vLLM / Qwen 3.5-35B",
    builtin: true,
    localModel: {
      type: "openai-compatible",
      provider: "vllm",
      model: "qwen3.5-35b",
      endpoint: "http://localhost:7999"
    },
    guardAgent: { model: "vllm/qwen3.5-35b" },
    defaultModel: "vllm/qwen3.5-35b"
  },
  {
    id: "minimax-cloud",
    name: "MiniMax M2.5 (Cloud)",
    builtin: true,
    localModel: {
      type: "openai-compatible",
      provider: "vllm",
      model: "qwen3.5-35b",
      endpoint: "http://localhost:7999"
    },
    guardAgent: { model: "vllm/qwen3.5-35b" },
    defaultModel: "minimax/MiniMax-M2.5-highspeed"
  }
];
var OPENCLAW_DIR = join3(process.env.HOME ?? "/tmp", ".openclaw");
var GUARDCLAW_CONFIG_PATH = join3(OPENCLAW_DIR, "guardclaw.json");
var OPENCLAW_CONFIG_PATH = join3(OPENCLAW_DIR, "openclaw.json");
function readConfig() {
  try {
    return JSON.parse(readFileSync(GUARDCLAW_CONFIG_PATH, "utf-8"));
  } catch {
    return {};
  }
}
function writeConfig(config) {
  try {
    mkdirSync(OPENCLAW_DIR, { recursive: true });
    writeFileSync(GUARDCLAW_CONFIG_PATH, JSON.stringify(config, null, 2), "utf-8");
  } catch {
  }
}
function readCurrentDefaultModel() {
  try {
    const raw = readFileSync(OPENCLAW_CONFIG_PATH, "utf-8");
    const config = JSON.parse(raw);
    const agents = config.agents;
    const defaults = agents?.defaults;
    const model = defaults?.model;
    if (typeof model === "string") return model.trim() || null;
    if (model && typeof model === "object") {
      const primary = model.primary;
      if (typeof primary === "string") return primary.trim() || null;
    }
    return null;
  } catch {
    return null;
  }
}
function writeDefaultModel(modelRef) {
  let raw;
  try {
    raw = readFileSync(OPENCLAW_CONFIG_PATH, "utf-8");
  } catch (err) {
    const code = err.code;
    if (code === "ENOENT") {
      return { ok: false, error: "openclaw.json not found. Run: openclaw onboard" };
    }
    return { ok: false, error: `Failed to read openclaw.json: ${code ?? String(err)}` };
  }
  let config;
  try {
    config = JSON.parse(raw);
  } catch {
    return {
      ok: false,
      error: "openclaw.json parse failed (may use JSON5). Run: openclaw models set " + modelRef
    };
  }
  if (!config.agents) config.agents = {};
  const agents = config.agents;
  if (!agents.defaults) agents.defaults = {};
  const defaults = agents.defaults;
  const currentModel = defaults.model;
  if (currentModel && typeof currentModel === "object") {
    currentModel.primary = modelRef;
  } else {
    defaults.model = modelRef;
  }
  try {
    writeFileSync(OPENCLAW_CONFIG_PATH, JSON.stringify(config, null, 2), "utf-8");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `Failed to write openclaw.json: ${String(err)}` };
  }
}
function listPresets() {
  const config = readConfig();
  const userPresets = config.presets ?? [];
  const activePreset = config.activePreset ?? null;
  return {
    presets: [...BUILTIN_PRESETS, ...userPresets],
    activePreset,
    currentDefaultModel: readCurrentDefaultModel()
  };
}
function applyPreset(id, opts) {
  const config = readConfig();
  const userPresets = config.presets ?? [];
  const allPresets = [...BUILTIN_PRESETS, ...userPresets];
  const preset = allPresets.find((p) => p.id === id);
  if (!preset) return { ok: false, error: `Preset not found: ${id}` };
  const currentGuardAgent = getLiveConfig().guardAgent;
  updateLiveConfig({
    localModel: { ...preset.localModel, enabled: true },
    guardAgent: { ...currentGuardAgent, model: preset.guardAgent.model }
  });
  const privacy = config.privacy ?? {};
  privacy.localModel = { ...preset.localModel, enabled: true };
  const existingGA = privacy.guardAgent ?? {};
  privacy.guardAgent = { ...existingGA, model: preset.guardAgent.model };
  config.privacy = privacy;
  config.activePreset = id;
  writeConfig(config);
  if (preset.defaultModel && opts?.applyDefaultModel) {
    const result = writeDefaultModel(preset.defaultModel);
    if (result.ok) {
      return { ok: true, defaultModelApplied: true, needsRestart: true };
    }
    return { ok: true, defaultModelApplied: false, defaultModelError: result.error };
  }
  return { ok: true };
}
function saveCurrentAsPreset(name) {
  const trimmed = name.trim();
  if (!trimmed) return { ok: false, error: "name required" };
  const liveConfig = getLiveConfig();
  const lm = liveConfig.localModel;
  const currentDefault = readCurrentDefaultModel();
  const id = trimmed.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/-+$/, "") + "-" + Date.now();
  const preset = {
    id,
    name: trimmed,
    localModel: {
      type: lm?.type ?? "openai-compatible",
      provider: lm?.provider ?? "",
      model: lm?.model ?? "",
      endpoint: lm?.endpoint ?? "",
      ...lm?.apiKey ? { apiKey: lm.apiKey } : {}
    },
    guardAgent: {
      model: liveConfig.guardAgent?.model ?? ""
    },
    ...currentDefault ? { defaultModel: currentDefault } : {}
  };
  const config = readConfig();
  const userPresets = config.presets ?? [];
  userPresets.push(preset);
  config.presets = userPresets;
  config.activePreset = id;
  writeConfig(config);
  return { ok: true, id };
}
function deletePreset(id) {
  if (BUILTIN_PRESETS.some((p) => p.id === id)) {
    return { ok: false, error: "Cannot delete built-in preset" };
  }
  const config = readConfig();
  const userPresets = config.presets ?? [];
  const idx = userPresets.findIndex((p) => p.id === id);
  if (idx === -1) return { ok: false, error: "Preset not found" };
  userPresets.splice(idx, 1);
  config.presets = userPresets;
  if (config.activePreset === id) delete config.activePreset;
  writeConfig(config);
  return { ok: true };
}

// src/routers/configurable.ts
function getOptions(routerId, pluginConfig) {
  const privacy = pluginConfig?.privacy ?? {};
  const routers = privacy.routers ?? {};
  const reg = routers[routerId];
  return reg?.options ?? {};
}
function getPrivacyConfig2(pluginConfig) {
  return pluginConfig?.privacy ?? {};
}
function checkKeywords2(text, keywords) {
  for (const kw of keywords.S3 ?? []) {
    if (getKeywordRegex(kw).test(text)) {
      return { level: "S3", reason: `S3 keyword: ${kw}` };
    }
  }
  for (const kw of keywords.S2 ?? []) {
    if (getKeywordRegex(kw).test(text)) {
      return { level: "S2", reason: `S2 keyword: ${kw}` };
    }
  }
  return { level: "S1" };
}
function checkPatterns2(text, patterns) {
  for (const pat of patterns.S3 ?? []) {
    try {
      if (new RegExp(pat, "i").test(text)) {
        return { level: "S3", reason: `S3 pattern: ${pat}` };
      }
    } catch {
    }
  }
  for (const pat of patterns.S2 ?? []) {
    try {
      if (new RegExp(pat, "i").test(text)) {
        return { level: "S2", reason: `S2 pattern: ${pat}` };
      }
    } catch {
    }
  }
  return { level: "S1" };
}
async function classifyWithPrompt(message, systemPrompt, pluginConfig) {
  const pCfg = getPrivacyConfig2(pluginConfig);
  const lm = pCfg.localModel;
  if (!lm?.enabled || !lm.endpoint) return null;
  try {
    const raw = await callChatCompletion(
      lm.endpoint,
      lm.model ?? "",
      [
        { role: "system", content: systemPrompt },
        { role: "user", content: message }
      ],
      {
        temperature: 0,
        maxTokens: 256,
        apiKey: lm.apiKey,
        providerType: lm.type ?? "openai-compatible",
        customModule: lm.module
      }
    );
    const text = raw.text.trim();
    const jsonMatch = text.match(/\{[\s\S]*?\}/);
    if (!jsonMatch) return null;
    const parsed = JSON.parse(jsonMatch[0]);
    const level = String(parsed.level ?? "S1").toUpperCase();
    if (level === "S2" || level === "S3") {
      return { level, reason: parsed.reason ?? "LLM classification" };
    }
    return { level: "S1" };
  } catch {
    return null;
  }
}
function resolveTargetForLevel(level, pluginConfig) {
  const pCfg = getPrivacyConfig2(pluginConfig);
  if (level === "S3") {
    const guardCfg = getGuardAgentConfig(pCfg);
    const defaultProvider = pCfg.localModel?.provider ?? "ollama";
    return {
      provider: guardCfg?.provider ?? defaultProvider,
      model: guardCfg?.modelName ?? pCfg.localModel?.model ?? "openbmb/minicpm4.1"
    };
  }
  const s2Policy = pCfg.s2Policy ?? "proxy";
  if (s2Policy === "local") {
    const guardCfg = getGuardAgentConfig(pCfg);
    const defaultProvider = pCfg.localModel?.provider ?? "ollama";
    return {
      provider: guardCfg?.provider ?? defaultProvider,
      model: guardCfg?.modelName ?? pCfg.localModel?.model ?? "openbmb/minicpm4.1"
    };
  }
  return { provider: "guardclaw-privacy", model: "" };
}
function createConfigurableRouter(id) {
  return {
    id,
    async detect(context, pluginConfig) {
      const opts = getOptions(id, pluginConfig);
      const text = context.message ?? "";
      const levels = [];
      const reasons = [];
      if (opts.keywords && text) {
        const kw = checkKeywords2(text, opts.keywords);
        if (kw.level !== "S1") {
          levels.push(kw.level);
          if (kw.reason) reasons.push(kw.reason);
        }
      }
      if (opts.patterns && text) {
        const pat = checkPatterns2(text, opts.patterns);
        if (pat.level !== "S1") {
          levels.push(pat.level);
          if (pat.reason) reasons.push(pat.reason);
        }
      }
      if (opts.prompt && text) {
        const llm = await classifyWithPrompt(text, opts.prompt, pluginConfig);
        if (llm && llm.level !== "S1") {
          levels.push(llm.level);
          if (llm.reason) reasons.push(llm.reason);
        }
      }
      if (levels.length === 0) {
        return { level: "S1", action: "passthrough", reason: "No match" };
      }
      const finalLevel = maxLevel(...levels);
      const action = opts.action ?? "redirect";
      let target;
      if (finalLevel !== "S1" && action === "redirect") {
        target = resolveTargetForLevel(finalLevel, pluginConfig);
      }
      return {
        level: finalLevel,
        action,
        target,
        reason: reasons.join("; "),
        confidence: levels.some((l) => l !== "S1") ? 0.8 : 0.5
      };
    }
  };
}

// src/stats-dashboard.ts
var GUARDCLAW_CONFIG_PATH2 = join4(process.env.HOME ?? "/tmp", ".openclaw", "guardclaw.json");
function saveGuardClawConfig(privacy) {
  try {
    const dir = join4(process.env.HOME ?? "/tmp", ".openclaw");
    mkdirSync2(dir, { recursive: true });
    let existing = {};
    try {
      existing = JSON.parse(readFileSync2(GUARDCLAW_CONFIG_PATH2, "utf-8"));
    } catch {
    }
    const updated = { ...existing, privacy };
    writeFileSync2(GUARDCLAW_CONFIG_PATH2, JSON.stringify(updated, null, 2), "utf-8");
  } catch {
  }
}
var deps = null;
function initDashboard(d) {
  deps = d;
}
function readBody(req) {
  return new Promise((resolve2, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve2(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}
function json(res, data, status = 200) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}
function html(res, body) {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(body);
}
async function statsHttpHandler(req, res) {
  const url = req.url ?? "";
  const parsedUrl = new URL(url, "http://localhost");
  const reqPath = parsedUrl.pathname;
  const base = "/plugins/guardclaw/stats";
  if (!reqPath.startsWith(base)) return false;
  const sub = reqPath.slice(base.length) || "/";
  if (req.method === "GET" && sub === "/") {
    html(res, dashboardHtml());
    return true;
  }
  if (req.method === "GET" && sub === "/api/summary") {
    const collector = getGlobalCollector();
    if (!collector) {
      json(res, { error: "not initialized" }, 503);
      return true;
    }
    json(res, collector.getSummary());
    return true;
  }
  if (req.method === "GET" && sub === "/api/hourly") {
    const collector = getGlobalCollector();
    if (!collector) {
      json(res, { error: "not initialized" }, 503);
      return true;
    }
    json(res, collector.getHourly());
    return true;
  }
  if (req.method === "GET" && sub === "/api/sessions") {
    const collector = getGlobalCollector();
    if (!collector) {
      json(res, { error: "not initialized" }, 503);
      return true;
    }
    json(res, collector.getSessionStats());
    return true;
  }
  if (req.method === "GET" && sub === "/api/current-loop-highest-level") {
    const sessionKey = parsedUrl.searchParams.get("sessionKey") ?? void 0;
    json(res, getCurrentLoopHighestLevel(sessionKey));
    return true;
  }
  if (req.method === "GET" && sub === "/api/last-turn-tokens") {
    const sessionKey = parsedUrl.searchParams.get("sessionKey") ?? void 0;
    const data = getLastTurnTokens(sessionKey);
    if (!data) {
      json(res, { error: "no last-turn router tokens yet" }, 404);
      return true;
    }
    json(res, data);
    return true;
  }
  if (req.method === "GET" && sub === "/api/reply-model-origin") {
    const sessionKey = parsedUrl.searchParams.get("sessionKey") ?? void 0;
    const origin = getLastReplyModelOrigin(sessionKey);
    const loopSummary = getLastReplyLoopSummary(sessionKey);
    if (!origin || !loopSummary) {
      json(res, { error: "no reply-model-origin data yet" }, 404);
      return true;
    }
    json(res, {
      sessionKey: origin.sessionKey,
      timestamp: origin.timestamp,
      provider: origin.provider,
      model: origin.model,
      origin: origin.origin,
      reason: origin.reason,
      loopTotalTokens: loopSummary.loopTotalTokens,
      loopLocalTokens: loopSummary.loopLocalTokens,
      loopCloudTokens: loopSummary.loopCloudTokens,
      routerTokens: loopSummary.routerTokens
    });
    return true;
  }
  if (req.method === "POST" && sub === "/api/reset") {
    const collector = getGlobalCollector();
    if (!collector) {
      json(res, { error: "not initialized" }, 503);
      return true;
    }
    await collector.reset();
    json(res, { ok: true });
    return true;
  }
  if (req.method === "GET" && sub === "/api/detections") {
    const states = getAllSessionStates();
    const events = [];
    states.forEach((state) => {
      for (const d of state.detectionHistory) {
        events.push({
          sessionKey: state.sessionKey,
          level: d.level,
          checkpoint: d.checkpoint,
          reason: d.reason,
          timestamp: d.timestamp
        });
      }
    });
    events.sort((a, b) => b.timestamp - a.timestamp);
    json(res, events.slice(0, 500));
    return true;
  }
  if (req.method === "GET" && sub === "/api/config") {
    const liveConfig = getLiveConfig();
    const cfgAny = liveConfig;
    json(res, {
      privacy: {
        enabled: liveConfig.enabled,
        localModel: liveConfig.localModel,
        guardAgent: liveConfig.guardAgent,
        s2Policy: liveConfig.s2Policy,
        proxyPort: liveConfig.proxyPort,
        checkpoints: liveConfig.checkpoints,
        rules: liveConfig.rules,
        localProviders: liveConfig.localProviders,
        modelPricing: liveConfig.modelPricing,
        session: liveConfig.session,
        routers: cfgAny.routers,
        pipeline: cfgAny.pipeline
      }
    });
    return true;
  }
  if (req.method === "POST" && sub === "/api/config") {
    if (!deps) {
      json(res, { error: "dashboard not initialized" }, 503);
      return true;
    }
    try {
      const body = JSON.parse(await readBody(req));
      if (body.privacy) {
        updateLiveConfig(body.privacy);
        const existingPrivacy = deps.pluginConfig.privacy ?? {};
        const incomingRouters = body.privacy.routers;
        const incomingPipeline = body.privacy.pipeline;
        if (incomingRouters) {
          body.privacy.routers = {
            ...existingPrivacy.routers ?? {},
            ...incomingRouters
          };
        }
        if (incomingPipeline) {
          body.privacy.pipeline = {
            ...existingPrivacy.pipeline ?? {},
            ...incomingPipeline
          };
        }
        const mergedPrivacy = { ...existingPrivacy, ...body.privacy };
        saveGuardClawConfig(mergedPrivacy);
        if (body.privacy.routers && deps.pipeline) {
          const routers = body.privacy.routers;
          for (const [id, reg] of Object.entries(routers)) {
            if (reg.type === "configurable" && !deps.pipeline.hasRouter(id)) {
              deps.pipeline.register(
                createConfigurableRouter(id),
                reg
              );
            }
          }
          const mergedPrivacy2 = { ...existingPrivacy, ...body.privacy };
          deps.pipeline.configure({
            routers: mergedPrivacy2.routers,
            pipeline: mergedPrivacy2.pipeline
          });
          deps.pluginConfig.privacy = mergedPrivacy2;
        }
      }
      json(res, { ok: true });
    } catch (err) {
      json(res, { error: String(err) }, 400);
    }
    return true;
  }
  if (req.method === "GET" && sub === "/api/corrections") {
    json(res, { corrections: getCorrections() });
    return true;
  }
  if (req.method === "POST" && sub === "/api/corrections") {
    try {
      const body = JSON.parse(await readBody(req));
      if (!body.message || !body.predicted || !body.corrected) {
        json(res, { error: "message, predicted, and corrected are required" }, 400);
        return true;
      }
      const validLevels = ["S1", "S2", "S3"];
      if (!validLevels.includes(body.predicted) || !validLevels.includes(body.corrected)) {
        json(res, { error: "predicted and corrected must be S1, S2, or S3" }, 400);
        return true;
      }
      if (body.predicted === body.corrected) {
        json(res, { error: "predicted and corrected must differ" }, 400);
        return true;
      }
      const correction = await addCorrection({
        message: body.message,
        predicted: body.predicted,
        corrected: body.corrected,
        reason: body.reason
      });
      json(res, { ok: true, correction });
    } catch (err) {
      json(res, { error: String(err) }, 400);
    }
    return true;
  }
  if (req.method === "DELETE" && sub.startsWith("/api/corrections/")) {
    const id = sub.slice("/api/corrections/".length);
    if (!id) {
      json(res, { error: "correction ID required" }, 400);
      return true;
    }
    const deleted = deleteCorrection(id);
    json(res, { ok: deleted, id });
    return true;
  }
  const EDITABLE_PROMPTS = {
    "detection-system": {
      label: "Privacy Detection (S1/S2/S3 Classifier)",
      defaultContent: DEFAULT_DETECTION_SYSTEM_PROMPT
    },
    "token-saver-judge": {
      label: "Token-Saver (Task Complexity Judge)",
      defaultContent: DEFAULT_JUDGE_PROMPT
    },
    "pii-extraction": {
      label: "PII Extraction Engine",
      defaultContent: DEFAULT_PII_EXTRACTION_PROMPT
    }
  };
  if (req.method === "GET" && sub === "/api/prompts") {
    const result = {};
    for (const [name, meta] of Object.entries(EDITABLE_PROMPTS)) {
      const fromDisk = readPromptFromDisk(name);
      result[name] = {
        label: meta.label,
        content: fromDisk ?? meta.defaultContent,
        isCustom: fromDisk !== null,
        defaultContent: meta.defaultContent
      };
    }
    json(res, result);
    return true;
  }
  if (req.method === "POST" && sub === "/api/prompts") {
    try {
      const body = JSON.parse(await readBody(req));
      if (!body.name || typeof body.content !== "string") {
        json(res, { error: "name and content required" }, 400);
        return true;
      }
      if (!EDITABLE_PROMPTS[body.name] && !body.name.startsWith("custom-")) {
        json(res, { error: `Unknown prompt: ${body.name}` }, 400);
        return true;
      }
      writePrompt(body.name, body.content);
      json(res, { ok: true });
    } catch (err) {
      json(res, { error: String(err) }, 400);
    }
    return true;
  }
  if (req.method === "POST" && sub === "/api/test-classify") {
    if (!deps?.pipeline) {
      json(res, { error: "pipeline not initialized" }, 503);
      return true;
    }
    try {
      const body = JSON.parse(await readBody(req));
      if (!body.message?.trim()) {
        json(res, { error: "message required" }, 400);
        return true;
      }
      const checkpoint = body.checkpoint ?? "onUserMessage";
      if (body.router) {
        const decision = await deps.pipeline.runSingle(
          body.router,
          { checkpoint, message: body.message, sessionKey: "__test__" },
          deps.pluginConfig
        );
        if (!decision) {
          json(res, { error: `Router not found: ${body.router}` }, 404);
          return true;
        }
        json(res, {
          level: decision.level,
          action: decision.action,
          target: decision.target,
          reason: decision.reason,
          confidence: decision.confidence,
          routerId: decision.routerId
        });
      } else {
        const decision = await deps.pipeline.run(
          checkpoint,
          { checkpoint, message: body.message, sessionKey: "__test__" },
          deps.pluginConfig
        );
        json(res, {
          level: decision.level,
          action: decision.action,
          target: decision.target,
          reason: decision.reason,
          confidence: decision.confidence,
          routerId: decision.routerId
        });
      }
    } catch (err) {
      json(res, { error: String(err) }, 500);
    }
    return true;
  }
  if (req.method === "GET" && sub === "/api/presets") {
    json(res, listPresets());
    return true;
  }
  if (req.method === "POST" && sub === "/api/presets/apply") {
    try {
      const body = JSON.parse(await readBody(req));
      if (!body.id) {
        json(res, { error: "id required" }, 400);
        return true;
      }
      const result = applyPreset(body.id, { applyDefaultModel: body.applyDefaultModel });
      json(res, result, result.ok ? 200 : 404);
    } catch (err) {
      json(res, { error: String(err) }, 400);
    }
    return true;
  }
  if (req.method === "POST" && sub === "/api/presets/save") {
    try {
      const body = JSON.parse(await readBody(req));
      if (!body.name?.trim()) {
        json(res, { error: "name required" }, 400);
        return true;
      }
      json(res, saveCurrentAsPreset(body.name));
    } catch (err) {
      json(res, { error: String(err) }, 400);
    }
    return true;
  }
  if (req.method === "DELETE" && sub.startsWith("/api/presets/")) {
    const presetId = decodeURIComponent(sub.slice("/api/presets/".length));
    if (!presetId) {
      json(res, { error: "id required" }, 400);
      return true;
    }
    const result = deletePreset(presetId);
    json(res, result, result.ok ? 200 : 400);
    return true;
  }
  return false;
}
function dashboardHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GuardClaw Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  :root{--bg-body:#ffffff;--bg-surface:#f9f9fa;--bg-card:#ffffff;--bg-input:#eff1f5;--text-primary:#1a1a1a;--text-secondary:#6e6e80;--text-tertiary:#9ca3af;--border-subtle:#e5e5e5;--accent:#2563eb;--accent-hover:#1d4ed8;--radius-sm:6px;--radius-md:12px;--radius-lg:16px;--shadow-sm:0 1px 2px 0 rgba(0,0,0,.05);--shadow-card:0 2px 8px rgba(0,0,0,.04);--shadow-float:0 10px 15px -3px rgba(0,0,0,.08),0 4px 6px -2px rgba(0,0,0,.04);--font-sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;--font-mono:'JetBrains Mono','SFMono-Regular',ui-monospace,monospace}
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:var(--font-sans);background:var(--bg-surface);color:var(--text-primary);min-height:100vh;-webkit-font-smoothing:antialiased;line-height:1.6}

  .header{padding:12px 24px;background:rgba(255,255,255,.85);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border-bottom:1px solid var(--border-subtle);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:50}
  .header-left{display:flex;align-items:center;gap:14px}
  .header h1{font-size:18px;font-weight:700;letter-spacing:-.01em;color:var(--text-primary)}
  .header-right{display:flex;align-items:center;gap:14px;font-size:12px;color:var(--text-tertiary)}
  .status-dot{width:8px;height:8px;border-radius:50%;background:#22c55e;display:inline-block;flex-shrink:0;box-shadow:0 0 0 2px rgba(34,197,94,.2)}
  .status-dot.err{background:#ef4444;box-shadow:0 0 0 2px rgba(239,68,68,.2)}
  .status-dot.warn{background:#f59e0b;box-shadow:0 0 0 2px rgba(245,158,11,.2)}

  .tabs{display:flex;gap:0;padding:0 24px;background:var(--bg-card);border-bottom:1px solid var(--border-subtle);overflow-x:auto}
  .tab{padding:12px 20px;cursor:pointer;border-bottom:2px solid transparent;color:var(--text-secondary);font-size:13px;font-weight:500;white-space:nowrap;transition:color .15s,border-color .15s}
  .tab.active{color:var(--accent);border-bottom-color:var(--accent)}
  .tab:hover{color:var(--text-primary)}

  .panel{display:none;padding:24px}
  .panel.active{display:block}

  .cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}
  @media(max-width:1000px){.cards{grid-template-columns:repeat(3,1fr)}}
  @media(max-width:700px){.cards{grid-template-columns:repeat(2,1fr)}}
  .card{background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:16px 18px;box-shadow:var(--shadow-sm);transition:box-shadow .2s,transform .2s}
  .card:hover{box-shadow:var(--shadow-card);transform:translateY(-1px)}
  .card-label{font-size:11px;color:var(--text-tertiary);text-transform:uppercase;letter-spacing:.05em;font-weight:600;margin-bottom:6px}
  .card-value{font-size:24px;font-weight:700;letter-spacing:-.02em;color:var(--text-primary)}
  .card-sub{font-size:11px;color:var(--text-tertiary);margin-top:4px}
  .card.cloud .card-value{color:#2563eb}
  .card.local .card-value{color:#059669}
  .card.proxy .card-value{color:#d97706}
  .card.privacy .card-value{color:#7c3aed}
  .card.cost .card-value{color:#dc2626}

  .chart-wrap{background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:16px 18px;margin-bottom:20px;box-shadow:var(--shadow-sm)}
  .chart-wrap h3{font-size:12px;color:var(--text-secondary);font-weight:600;margin-bottom:10px}

  .data-table{width:100%;border-collapse:collapse;background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:var(--radius-md);overflow:hidden}
  .data-table th,.data-table td{padding:10px 14px;font-size:13px;text-align:right}
  .data-table th{background:var(--bg-surface);color:var(--text-secondary);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
  .data-table th:first-child,.data-table td:first-child{text-align:left}
  .data-table tr:not(:last-child) td{border-bottom:1px solid var(--border-subtle)}
  .data-table tbody tr:hover{background:rgba(37,99,235,.02)}
  #detections-panel .data-table th,#detections-panel .data-table td{text-align:left}

  .info-bar{display:flex;gap:24px;padding:14px 0;font-size:12px;color:var(--text-tertiary)}

  .level-tag{display:inline-block;font-size:11px;font-weight:600;padding:3px 10px;border-radius:99px}
  .level-S1{background:rgba(37,99,235,.08);color:#2563eb}
  .level-S2{background:rgba(217,119,6,.08);color:#d97706}
  .level-S3{background:rgba(5,150,105,.08);color:#059669}
  .checkpoint-tag{font-size:11px;padding:3px 8px;border-radius:99px;background:var(--bg-input);color:var(--text-secondary);font-weight:500}
  .session-key{font-family:var(--font-mono);font-size:12px;color:var(--text-secondary)}

  .empty-state{text-align:center;color:var(--text-tertiary);padding:48px 0;font-size:14px}

  .filter-bar{display:flex;gap:8px;margin-bottom:18px}
  .filter-btn{padding:7px 16px;border-radius:99px;border:1px solid var(--border-subtle);background:var(--bg-card);color:var(--text-secondary);cursor:pointer;font-size:12px;font-weight:500;transition:all .15s}
  .filter-btn.active{background:var(--text-primary);color:#fff;border-color:var(--text-primary)}
  .filter-btn:hover{border-color:#d1d5db;color:var(--text-primary)}

  .config-section{background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:18px 20px;margin-bottom:14px;box-shadow:var(--shadow-sm)}
  .config-section h3{font-size:11px;color:var(--text-secondary);margin-bottom:14px;text-transform:uppercase;letter-spacing:.05em;font-weight:700}
  .field{margin-bottom:16px}
  .field label{display:block;font-size:12px;color:var(--text-secondary);margin-bottom:6px;font-weight:500}
  .field input,.field select{width:100%;padding:10px 14px;background:var(--bg-input);border:1px solid transparent;border-radius:var(--radius-sm);color:var(--text-primary);font-size:13px;outline:none;transition:all .15s}
  .field select{appearance:none;-webkit-appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%236e6e80' d='M2 4l4 4 4-4'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 14px center;padding-right:36px}
  .field input:hover,.field select:hover{background:#eaecf1}
  .field input:focus,.field select:focus{background:#fff;border-color:transparent;box-shadow:0 0 0 3px rgba(37,99,235,.15)}

  .tag-list{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px;min-height:32px}
  .tag{background:var(--bg-input);color:var(--text-primary);padding:5px 12px;border-radius:99px;font-size:12px;font-weight:500;display:flex;align-items:center;gap:6px;border:1px solid var(--border-subtle)}
  .tag button{background:none;border:none;color:var(--text-tertiary);cursor:pointer;font-size:14px;line-height:1;transition:color .15s}
  .tag button:hover{color:#ef4444}
  .add-row{display:flex;gap:10px;margin-top:10px;align-items:center}
  .add-row input{flex:1;min-width:0}

  .btn{padding:10px 20px;border-radius:var(--radius-sm);border:none;cursor:pointer;font-size:13px;font-weight:500;transition:all .15s;white-space:nowrap;flex-shrink:0}
  .btn-primary{background:var(--text-primary);color:#fff}
  .btn-primary:hover{background:#333}
  .btn-sm{padding:8px 16px;font-size:12px}
  .btn-outline{background:var(--bg-card);border:1px solid var(--border-subtle);color:var(--text-primary)}
  .btn-outline:hover{border-color:#d1d5db;background:var(--bg-surface)}
  .save-bar{display:flex;justify-content:flex-end;gap:10px;padding-top:14px;margin-top:10px}

  .badge{display:inline-block;font-size:10px;padding:3px 8px;border-radius:99px;margin-left:8px;vertical-align:middle;font-weight:600}
  .badge-hot{background:rgba(5,150,105,.1);color:#059669}

  .toast{position:fixed;bottom:24px;right:24px;background:var(--text-primary);color:#fff;padding:14px 22px;border-radius:var(--radius-md);font-size:13px;font-weight:500;display:none;z-index:100;box-shadow:0 12px 40px rgba(0,0,0,.15)}
  .toast.error{background:#dc2626}

  .rules-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  @media(max-width:700px){.rules-grid{grid-template-columns:1fr}}
  .rules-col{background:var(--bg-surface);border:1px solid var(--border-subtle);border-radius:var(--radius-sm);padding:14px}
  .rules-col h4{font-size:11px;color:var(--text-tertiary);margin-bottom:10px;text-transform:uppercase;letter-spacing:.05em;font-weight:700;border-bottom:1px solid var(--border-subtle);padding-bottom:8px}

  .toggle-bar{display:flex;align-items:center;justify-content:space-between;background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:14px 18px;margin-bottom:14px;box-shadow:var(--shadow-sm)}
  .toggle-bar label{font-size:13px;color:var(--text-primary);font-weight:500}
  .toggle{position:relative;display:inline-block;width:44px;height:24px;flex-shrink:0}
  .toggle input{opacity:0;width:0;height:0}
  .toggle .slider{position:absolute;inset:0;background:#d1d5db;border-radius:12px;cursor:pointer;transition:.2s}
  .toggle .slider::before{content:'';position:absolute;width:18px;height:18px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s;box-shadow:0 1px 3px rgba(0,0,0,.2)}
  .toggle input:checked+.slider{background:var(--accent)}
  .toggle input:checked+.slider::before{transform:translateX(20px)}

  .chip-group{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
  .chip{padding:7px 14px;border-radius:99px;font-size:12px;cursor:pointer;border:1px solid var(--border-subtle);background:var(--bg-card);color:var(--text-secondary);font-weight:500;transition:all .15s}
  .chip.active{background:var(--text-primary);color:#fff;border-color:var(--text-primary)}
  .chip:hover{border-color:#d1d5db;color:var(--text-primary)}

  .router-card{background:var(--bg-surface);border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:16px;margin-bottom:10px;transition:border-color .15s}
  .router-card:hover{border-color:#d1d5db}
  .router-card .rc-head{display:flex;align-items:center;gap:8px}
  .router-card .rc-name{font-size:13px;color:var(--text-primary);font-weight:600}
  .router-card .rc-type{font-size:11px;color:var(--text-tertiary)}
  .router-card .rc-del{margin-left:auto;background:none;border:none;color:var(--text-tertiary);cursor:pointer;font-size:16px;line-height:1;transition:color .15s}
  .router-card .rc-del:hover{color:#ef4444}
  .router-card .rc-module{font-size:11px;color:var(--text-tertiary);margin-top:4px}

  .field-toggle{display:flex;align-items:center;gap:12px;margin-bottom:14px}
  .field-toggle>label{font-size:13px;color:var(--text-secondary);margin-bottom:0}
  .hint{font-size:11px;color:var(--text-tertiary);margin-top:4px}

  .prompt-editor{width:100%;min-height:200px;padding:16px 18px;background:var(--bg-input);border:1px solid transparent;border-radius:var(--radius-md);color:var(--text-primary);font-family:var(--font-mono);font-size:12px;line-height:1.6;resize:vertical;outline:none;tab-size:2;transition:all .15s}
  .prompt-editor:hover{background:#eaecf1}
  .prompt-editor:focus{background:#fff;box-shadow:0 0 0 3px rgba(37,99,235,.15)}
  .prompt-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
  .prompt-header h4{font-size:13px;color:var(--text-primary);font-weight:600}
  .prompt-actions{display:flex;gap:6px}
  .custom-badge{font-size:10px;padding:3px 8px;border-radius:99px;background:rgba(37,99,235,.08);color:var(--accent);font-weight:600;margin-left:8px}

  .test-panel{background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:18px 20px;margin-bottom:14px;box-shadow:var(--shadow-sm)}
  .test-input{width:100%;min-height:80px;padding:14px 16px;background:var(--bg-input);border:1px solid transparent;border-radius:var(--radius-md);color:var(--text-primary);font-size:13px;resize:vertical;outline:none;transition:all .15s}
  .test-input:hover{background:#eaecf1}
  .test-input:focus{background:#fff;box-shadow:0 0 0 3px rgba(37,99,235,.15)}
  .test-result{margin-top:18px;padding:18px 20px;background:var(--bg-surface);border-radius:var(--radius-md);border:1px solid var(--border-subtle);display:none}
  .test-result.visible{display:block}
  .test-result-row{display:flex;justify-content:space-between;padding:10px 0;font-size:13px;border-bottom:1px solid var(--border-subtle)}
  .test-result-row:last-child{border-bottom:none}
  .test-result-label{color:var(--text-secondary)}
  .test-result-value{color:var(--text-primary);font-weight:600}
  .test-loading{color:var(--text-secondary);font-size:13px;padding:14px 0}

  .tier-grid{display:grid;grid-template-columns:120px 1fr 1fr;gap:10px;align-items:center}
  .tier-grid .tier-label{font-size:12px;color:var(--text-secondary);font-weight:600}
  .tier-grid input{padding:9px 14px;background:var(--bg-input);border:1px solid transparent;border-radius:var(--radius-sm);color:var(--text-primary);font-size:12px;outline:none;transition:all .15s}
  .tier-grid input:hover{background:#eaecf1}
  .tier-grid input:focus{background:#fff;box-shadow:0 0 0 3px rgba(37,99,235,.15)}
  .tier-grid-header{font-size:11px;color:var(--text-tertiary);text-transform:uppercase;letter-spacing:.06em;font-weight:700;padding-bottom:8px}

  .section-collapse{cursor:pointer;user-select:none}
  .section-collapse::before{content:'\\25BC';display:inline-block;margin-right:8px;font-size:10px;transition:transform .2s;color:var(--text-tertiary)}
  .section-collapse.collapsed::before{transform:rotate(-90deg)}
  .section-body{overflow:hidden;transition:max-height .3s ease}
  .section-body.collapsed{max-height:0 !important;padding:0;overflow:hidden}

  .router-section{background:var(--bg-card);border-radius:var(--radius-md);margin-bottom:14px;border:1px solid var(--border-subtle);overflow:hidden;box-shadow:var(--shadow-sm)}
  .router-section-header{display:flex;align-items:center;gap:10px;padding:14px 18px;cursor:pointer;user-select:none;transition:background .15s}
  .router-section-header:hover{background:var(--bg-surface)}
  .router-section-header h3{font-size:14px;color:var(--text-primary);font-weight:600;margin:0}
  .router-section-header .section-arrow{font-size:10px;color:var(--text-tertiary);transition:transform .2s;display:inline-block}
  .router-section-header.collapsed .section-arrow{transform:rotate(-90deg)}
  .router-id-badge{font-size:11px;padding:3px 10px;border-radius:99px;background:var(--bg-input);color:var(--text-secondary);font-family:var(--font-mono);font-weight:500}
  .router-section-body{padding:0 18px 18px}
  .router-section-body.collapsed{display:none}
  .subsection{margin-bottom:18px;padding-bottom:16px;border-bottom:1px solid var(--border-subtle)}
  .subsection:last-of-type{border-bottom:none;margin-bottom:0;padding-bottom:0}
  .subsection>h4{font-size:11px;color:var(--text-secondary);margin-bottom:10px;text-transform:uppercase;letter-spacing:.05em;font-weight:700}
  .add-custom-router{background:var(--bg-card);border:2px dashed var(--border-subtle);border-radius:var(--radius-md);padding:18px 20px;margin-bottom:14px;transition:border-color .15s}
  .add-custom-router:hover{border-color:#d1d5db}
  .btn-danger{background:#fef2f2;color:#dc2626;border:1px solid #fecaca}
  .btn-danger:hover{background:#fee2e2}
  .pipe-picker{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
  .pipe-pick-btn{padding:6px 14px;border-radius:99px;font-size:12px;cursor:pointer;border:1px dashed var(--border-subtle);background:var(--bg-card);color:var(--text-secondary);transition:all .15s;font-family:var(--font-mono);font-weight:500}
  .pipe-pick-btn:hover{border-color:var(--accent);color:var(--accent)}
  .pipe-pick-btn.in-use{opacity:.35;cursor:default;border-style:solid}
  .pipe-pick-btn.in-use:hover{border-color:var(--border-subtle);color:var(--text-secondary)}
  .tag.pipe-tag{cursor:grab;user-select:none}
  .tag.pipe-tag.dragging{opacity:.4}
  .adv-toggle{display:flex;align-items:center;gap:6px;cursor:pointer;user-select:none;font-size:12px;color:var(--text-tertiary);margin:18px 0 10px;padding:6px 0;font-weight:500}
  .adv-toggle:hover{color:var(--text-secondary)}
  .adv-toggle .adv-arrow{font-size:10px;transition:transform .2s;display:inline-block}
  .adv-toggle.open .adv-arrow{transform:rotate(90deg)}
  .adv-body{display:none}
  .adv-body.open{display:block}

  ::-webkit-scrollbar{width:6px;height:6px}
  ::-webkit-scrollbar-track{background:transparent}
  ::-webkit-scrollbar-thumb{background:#d1d5db;border-radius:3px}
  ::-webkit-scrollbar-thumb:hover{background:#9ca3af}
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <h1 data-i18n="header.title">GuardClaw Dashboard</h1>
  </div>
  <div class="header-right">
    <span class="status-dot warn" id="status-dot"></span>
    <span id="status-text" data-i18n="header.connecting">Connecting...</span>
    <span id="last-updated"></span>
    <button class="btn btn-sm btn-outline" onclick="refreshAll()" data-i18n="header.refresh">Refresh</button>
    <button class="btn btn-sm btn-outline" id="lang-toggle" onclick="setLang(LANG==='en'?'zh':'en')">\u4E2D\u6587</button>
  </div>
</div>

<div class="tabs">
  <div class="tab active" data-tab="stats" data-i18n="tab.overview">Overview</div>
  <div class="tab" data-tab="sessions" data-i18n="tab.sessions">Sessions</div>
  <div class="tab" data-tab="detections" data-i18n="tab.detections">Detection Log</div>
  <div class="tab" data-tab="rules"><span data-i18n="tab.rules">Router Rules</span> <span class="badge badge-hot">live</span></div>
  <div class="tab" data-tab="config"><span data-i18n="tab.config">Configuration</span> <span class="badge badge-hot">live</span></div>
</div>

<!-- Overview -->
<div id="stats-panel" class="panel active">
  <div class="cards">
    <div class="card cloud">
      <div class="card-label" data-i18n="overview.cloud">Cloud Tokens</div>
      <div class="card-value" id="cloud-tokens">-</div>
      <div class="card-sub" id="cloud-reqs">0 requests</div>
    </div>
    <div class="card local">
      <div class="card-label" data-i18n="overview.local">Local Tokens</div>
      <div class="card-value" id="local-tokens">-</div>
      <div class="card-sub" id="local-reqs">0 requests</div>
    </div>
    <div class="card proxy">
      <div class="card-label" data-i18n="overview.redacted">Redacted Tokens</div>
      <div class="card-value" id="proxy-tokens">-</div>
      <div class="card-sub" id="proxy-reqs">0 requests</div>
    </div>
    <div class="card privacy">
      <div class="card-label" data-i18n="overview.protection">Data Protection Rate</div>
      <div class="card-value" id="privacy-rate">-</div>
      <div class="card-sub" id="privacy-sub" data-i18n="overview.sub">of total tokens protected</div>
    </div>
    <div class="card cost">
      <div class="card-label" data-i18n="overview.cost">Cloud Cost</div>
      <div class="card-value" id="cloud-cost">-</div>
      <div class="card-sub" id="cloud-cost-sub" data-i18n="overview.cost_sub">estimated cloud API cost</div>
    </div>
  </div>
  <div class="chart-wrap">
    <h3 data-i18n="overview.chart">Hourly Token Usage</h3>
    <canvas id="hourlyChart" height="80"></canvas>
  </div>
  <table class="data-table">
    <thead><tr><th data-i18n="table.category">Category</th><th data-i18n="table.input">Input</th><th data-i18n="table.output">Output</th><th data-i18n="table.cache">Cache Read</th><th data-i18n="table.total">Total</th><th data-i18n="table.requests">Requests</th><th data-i18n="table.cost">Cost</th></tr></thead>
    <tbody id="detail-body"></tbody>
  </table>
  <h4 style="margin-top:18px;margin-bottom:6px;color:var(--text-secondary);" data-i18n="table.by_source">By Source (Router vs Task)</h4>
  <table class="data-table">
    <thead><tr><th data-i18n="table.source">Source</th><th data-i18n="table.input">Input</th><th data-i18n="table.output">Output</th><th data-i18n="table.cache">Cache Read</th><th data-i18n="table.total">Total</th><th data-i18n="table.requests">Requests</th><th data-i18n="table.cost">Cost</th></tr></thead>
    <tbody id="source-body"></tbody>
  </table>
  <div class="info-bar" id="info-bar"></div>
  <div style="text-align:right;margin-top:8px;">
    <button class="btn btn-sm btn-outline" onclick="resetStats()" data-i18n="overview.reset_btn">Reset Stats</button>
  </div>
</div>

<!-- Sessions -->
<div id="sessions-panel" class="panel">
  <table class="data-table">
    <thead><tr><th data-i18n="sessions.session">Session</th><th data-i18n="sessions.level">Level</th><th data-i18n="sessions.cloud">Cloud</th><th data-i18n="sessions.local">Local</th><th data-i18n="sessions.redacted">Redacted</th><th>Router</th><th>Task</th><th data-i18n="sessions.total">Total</th><th data-i18n="sessions.cost">Cost</th><th data-i18n="sessions.requests">Requests</th><th data-i18n="sessions.last_active">Last Active</th></tr></thead>
    <tbody id="sessions-body"><tr><td colspan="11" class="empty-state" data-i18n="sessions.empty">No session data yet</td></tr></tbody>
  </table>
</div>

<!-- Detection Log -->
<div id="detections-panel" class="panel">
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterDetections('all',this)" data-i18n="det.all">All</button>
    <button class="filter-btn" onclick="filterDetections('S1',this)">S1</button>
    <button class="filter-btn" onclick="filterDetections('S2',this)">S2</button>
    <button class="filter-btn" onclick="filterDetections('S3',this)">S3</button>
  </div>
  <table class="data-table">
    <thead><tr><th data-i18n="det.time">Time</th><th data-i18n="det.session">Session</th><th data-i18n="det.level">Level</th><th data-i18n="det.checkpoint">Checkpoint</th><th data-i18n="det.reason">Reason</th></tr></thead>
    <tbody id="detections-body"><tr><td colspan="5" class="empty-state" data-i18n="det.empty">No detections yet</td></tr></tbody>
  </table>
</div>

<!-- Router Rules -->
<div id="rules-panel" class="panel">

  <!-- Pipeline Test (full pipeline) -->
  <div class="test-panel">
    <h3 style="font-size:12px;color:var(--text-secondary);margin-bottom:14px;text-transform:uppercase;letter-spacing:.06em;font-weight:700" data-i18n="test.title">Test Classification</h3>
    <div class="hint" style="margin-bottom:10px" data-i18n="test.hint">Test how the router pipeline would classify a message (no changes applied).</div>
    <textarea class="test-input" id="test-message" data-i18n-ph="test.placeholder" placeholder="e.g. &quot;\u5E2E\u6211\u5206\u6790\u4E00\u4E0B\u8FD9\u4E2A\u6708\u7684\u5DE5\u8D44\u5355&quot; or &quot;write a poem about spring&quot;"></textarea>
    <div style="display:flex;gap:8px;margin-top:10px;align-items:center">
      <select id="test-checkpoint" style="padding:10px 36px 10px 14px;background:var(--bg-input) url(&quot;data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%236e6e80' d='M2 4l4 4 4-4'/%3E%3C/svg%3E&quot;) no-repeat right 14px center;border:1px solid transparent;border-radius:6px;color:var(--text-primary);font-size:12px;appearance:none;-webkit-appearance:none">
        <option value="onUserMessage" data-i18n-opt="ck.user_message">User Message</option>
        <option value="onToolCallProposed" data-i18n-opt="ck.before_tool">Before Tool Runs</option>
        <option value="onToolCallExecuted" data-i18n-opt="ck.after_tool">After Tool Runs</option>
      </select>
      <button class="btn btn-primary btn-sm" onclick="runTestClassify()" data-i18n="test.run">Run Test</button>
    </div>
    <div class="test-result" id="test-result">
      <div style="font-size:11px;text-transform:uppercase;color:var(--text-tertiary);letter-spacing:.06em;font-weight:700;margin-bottom:10px" data-i18n="test.merged">Merged Result</div>
      <div class="test-result-row"><span class="test-result-label" data-i18n="test.level">Level</span><span class="test-result-value" id="tr-level">-</span></div>
      <div class="test-result-row"><span class="test-result-label" data-i18n="test.action">Action</span><span class="test-result-value" id="tr-action">-</span></div>
      <div class="test-result-row"><span class="test-result-label" data-i18n="test.target">Target</span><span class="test-result-value" id="tr-target">-</span></div>
      <div class="test-result-row"><span class="test-result-label" data-i18n="test.deciding">Deciding Router</span><span class="test-result-value" id="tr-router">-</span></div>
      <div class="test-result-row"><span class="test-result-label" data-i18n="test.reason">Reason</span><span class="test-result-value" id="tr-reason">-</span></div>
      <div class="test-result-row"><span class="test-result-label" data-i18n="test.confidence">Confidence</span><span class="test-result-value" id="tr-confidence">-</span></div>
      <div id="tr-per-router"></div>
    </div>
    <div class="test-loading" id="test-loading" style="display:none" data-i18n="test.classifying">Classifying...</div>
  </div>

  <!-- Pipeline Order (Advanced) -->
  <div class="adv-toggle" onclick="toggleAdv(this)">
    <span class="adv-arrow">&#9654;</span> <span data-i18n="pipe.title">Router Execution Order (Advanced)</span>
  </div>
  <div class="adv-body">
    <div class="config-section">
      <div class="hint" style="margin-bottom:12px" data-i18n="pipe.hint">Click a router to add it to a stage. Drag tags to reorder. Click &times; to remove.</div>
      <div class="field">
        <label data-i18n="ck.user_message">User Message</label>
        <div class="tag-list" id="cfg-tags-pipe-um"></div>
        <div class="pipe-picker" id="pipe-picker-um"></div>
      </div>
      <div class="field">
        <label data-i18n="ck.before_tool">Before Tool Runs</label>
        <div class="tag-list" id="cfg-tags-pipe-tcp"></div>
        <div class="pipe-picker" id="pipe-picker-tcp"></div>
      </div>
      <div class="field">
        <label data-i18n="ck.after_tool">After Tool Runs</label>
        <div class="tag-list" id="cfg-tags-pipe-tce"></div>
        <div class="pipe-picker" id="pipe-picker-tce"></div>
      </div>
      <div class="save-bar"><button class="btn btn-primary btn-sm" onclick="savePipelineOrder()" data-i18n="pipe.save">Save Execution Order</button></div>
    </div>
  </div>

  <!-- \u2550\u2550\u2550 Privacy Router Card \u2550\u2550\u2550 -->
  <div class="router-section">
    <div class="router-section-header" onclick="toggleSection(this)">
      <span class="section-arrow">&#9660;</span>
      <h3 data-i18n="priv.title">Privacy Router</h3>
      <span class="router-id-badge">privacy</span>
    </div>
    <div class="router-section-body">
      <div class="hint" style="margin-bottom:14px" data-i18n="priv.desc">Detects sensitive data in messages and routes to local or redacted cloud models.</div>

      <div class="field-toggle" style="margin-bottom:18px">
        <label data-i18n="common.enabled">Enabled</label>
        <label class="toggle"><input type="checkbox" id="cfg-privacy-enabled" checked><span class="slider"></span></label>
      </div>

      <!-- Keywords (always visible) -->
      <div class="subsection">
        <h4 data-i18n="priv.keywords">Keywords</h4>
        <div class="rules-grid">
          <div class="rules-col">
            <h4 data-i18n-html="priv.s2">S2 &mdash; Sensitive (Redact &rarr; Cloud)</h4>
            <div class="field">
              <label data-i18n="priv.keywords">Keywords</label>
              <div class="tag-list" id="cfg-tags-kw-s2"></div>
              <div class="add-row">
                <input id="cfg-tags-kw-s2-input" placeholder="e.g. salary, phone number" onkeydown="if(event.key==='Enter'){event.preventDefault();addTag('kw-s2')}">
                <button class="btn btn-sm btn-outline" onclick="addTag('kw-s2')">Add</button>
              </div>
            </div>
          </div>
          <div class="rules-col">
            <h4 data-i18n-html="priv.s3">S3 &mdash; Confidential (Local Model Only)</h4>
            <div class="field">
              <label data-i18n="priv.keywords">Keywords</label>
              <div class="tag-list" id="cfg-tags-kw-s3"></div>
              <div class="add-row">
                <input id="cfg-tags-kw-s3-input" placeholder="e.g. SSN, bank account" onkeydown="if(event.key==='Enter'){event.preventDefault();addTag('kw-s3')}">
                <button class="btn btn-sm btn-outline" onclick="addTag('kw-s3')">Add</button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- LLM Prompts (privacy-specific) -->
      <div class="subsection">
        <h4 data-i18n="priv.llm_prompt">LLM Prompt</h4>
        <div class="hint" style="margin-bottom:12px" data-i18n="priv.llm_hint">Prompt used by the local LLM to classify data sensitivity (S1/S2/S3).</div>
        <div id="privacy-prompt-main"></div>
      </div>

      <!-- Per-router Test -->
      <div class="subsection">
        <h4 data-i18n="priv.test_title">Test (Privacy Router Only)</h4>
        <textarea class="test-input" id="test-privacy-message" data-i18n-ph="priv.test_ph" placeholder="Enter a message to test the privacy router alone..."></textarea>
        <div style="display:flex;gap:8px;margin-top:10px;align-items:center">
          <button class="btn btn-primary btn-sm" onclick="runRouterTest('privacy')" data-i18n="priv.test_btn">Test Privacy Router</button>
        </div>
        <div class="test-result" id="test-privacy-result">
          <div class="test-result-row"><span class="test-result-label" data-i18n="test.level">Level</span><span class="test-result-value" id="tr-privacy-level">-</span></div>
          <div class="test-result-row"><span class="test-result-label" data-i18n="test.action">Action</span><span class="test-result-value" id="tr-privacy-action">-</span></div>
          <div class="test-result-row"><span class="test-result-label" data-i18n="test.target">Target</span><span class="test-result-value" id="tr-privacy-target">-</span></div>
          <div class="test-result-row"><span class="test-result-label" data-i18n="test.reason">Reason</span><span class="test-result-value" id="tr-privacy-reason">-</span></div>
          <div class="test-result-row"><span class="test-result-label" data-i18n="test.confidence">Confidence</span><span class="test-result-value" id="tr-privacy-confidence">-</span></div>
        </div>
        <div class="test-loading" id="test-privacy-loading" style="display:none" data-i18n="test.testing">Testing...</div>
      </div>

      <!-- Advanced Configuration -->
      <div class="adv-toggle" onclick="toggleAdv(this)">
        <span class="adv-arrow">&#9654;</span> <span data-i18n="priv.adv">Advanced Configuration</span>
      </div>
      <div class="adv-body">

        <!-- When to Run -->
        <div class="subsection">
          <h4 data-i18n="priv.when">When to Run</h4>
          <div class="hint" style="margin-bottom:10px" data-i18n="priv.when_hint">Select which detectors run at each stage for the privacy router.</div>
          <div class="field">
            <label data-i18n="ck.user_message">User Message</label>
            <div class="chip-group" id="ck-um">
              <button class="chip" data-ck="um" data-det="ruleDetector" onclick="toggleChip(this)" data-i18n="priv.kw_regex">Keyword &amp; Regex</button>
              <button class="chip" data-ck="um" data-det="localModelDetector" onclick="toggleChip(this)" data-i18n="priv.llm_cls">LLM Classifier</button>
            </div>
          </div>
          <div class="field">
            <label data-i18n="ck.before_tool">Before Tool Runs</label>
            <div class="chip-group" id="ck-tcp">
              <button class="chip" data-ck="tcp" data-det="ruleDetector" onclick="toggleChip(this)" data-i18n="priv.kw_regex">Keyword &amp; Regex</button>
              <button class="chip" data-ck="tcp" data-det="localModelDetector" onclick="toggleChip(this)" data-i18n="priv.llm_cls">LLM Classifier</button>
            </div>
          </div>
          <div class="field">
            <label data-i18n="ck.after_tool">After Tool Runs</label>
            <div class="chip-group" id="ck-tce">
              <button class="chip" data-ck="tce" data-det="ruleDetector" onclick="toggleChip(this)" data-i18n="priv.kw_regex">Keyword &amp; Regex</button>
              <button class="chip" data-ck="tce" data-det="localModelDetector" onclick="toggleChip(this)" data-i18n="priv.llm_cls">LLM Classifier</button>
            </div>
          </div>
        </div>

        <!-- Regex Patterns, Sensitive Tool Names, Sensitive File Paths -->
        <div class="subsection">
          <h4 data-i18n="priv.det_rules">Detection Rules (Regex &amp; Tool Filters)</h4>
          <div class="rules-grid">
            <div class="rules-col">
              <h4 data-i18n-html="priv.s2">S2 &mdash; Sensitive (Redact &rarr; Cloud)</h4>
              <div class="field">
                <label data-i18n="priv.regex">Regex Patterns</label>
                <div class="tag-list" id="cfg-tags-pat-s2"></div>
                <div class="add-row">
                  <input id="cfg-tags-pat-s2-input" placeholder="e.g. \\d{3}-\\d{4}" onkeydown="if(event.key==='Enter'){event.preventDefault();addTag('pat-s2')}">
                  <button class="btn btn-sm btn-outline" onclick="addTag('pat-s2')">Add</button>
                </div>
              </div>
              <div class="field">
                <label data-i18n="priv.tools">Sensitive Tool Names</label>
                <div class="tag-list" id="cfg-tags-tool-s2"></div>
                <div class="add-row">
                  <input id="cfg-tags-tool-s2-input" placeholder="e.g. read_file, execute_sql" onkeydown="if(event.key==='Enter'){event.preventDefault();addTag('tool-s2')}">
                  <button class="btn btn-sm btn-outline" onclick="addTag('tool-s2')">Add</button>
                </div>
              </div>
              <div class="field">
                <label data-i18n="priv.paths">Sensitive File Paths</label>
                <div class="tag-list" id="cfg-tags-toolpath-s2"></div>
                <div class="add-row">
                  <input id="cfg-tags-toolpath-s2-input" placeholder="e.g. /secrets/, *.env" onkeydown="if(event.key==='Enter'){event.preventDefault();addTag('toolpath-s2')}">
                  <button class="btn btn-sm btn-outline" onclick="addTag('toolpath-s2')">Add</button>
                </div>
              </div>
            </div>
            <div class="rules-col">
              <h4 data-i18n-html="priv.s3">S3 &mdash; Confidential (Local Model Only)</h4>
              <div class="field">
                <label data-i18n="priv.regex">Regex Patterns</label>
                <div class="tag-list" id="cfg-tags-pat-s3"></div>
                <div class="add-row">
                  <input id="cfg-tags-pat-s3-input" placeholder="e.g. \\b\\d{3}-\\d{2}-\\d{4}\\b" onkeydown="if(event.key==='Enter'){event.preventDefault();addTag('pat-s3')}">
                  <button class="btn btn-sm btn-outline" onclick="addTag('pat-s3')">Add</button>
                </div>
              </div>
              <div class="field">
                <label data-i18n="priv.tools">Sensitive Tool Names</label>
                <div class="tag-list" id="cfg-tags-tool-s3"></div>
                <div class="add-row">
                  <input id="cfg-tags-tool-s3-input" placeholder="e.g. execute_command" onkeydown="if(event.key==='Enter'){event.preventDefault();addTag('tool-s3')}">
                  <button class="btn btn-sm btn-outline" onclick="addTag('tool-s3')">Add</button>
                </div>
              </div>
              <div class="field">
                <label data-i18n="priv.paths">Sensitive File Paths</label>
                <div class="tag-list" id="cfg-tags-toolpath-s3"></div>
                <div class="add-row">
                  <input id="cfg-tags-toolpath-s3-input" placeholder="e.g. /credentials/" onkeydown="if(event.key==='Enter'){event.preventDefault();addTag('toolpath-s3')}">
                  <button class="btn btn-sm btn-outline" onclick="addTag('toolpath-s3')">Add</button>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Personal Info Redaction Prompt -->
        <div class="subsection">
          <h4 data-i18n="priv.pii">Personal Info Redaction Prompt</h4>
          <div class="hint" style="margin-bottom:12px" data-i18n="priv.pii_hint">Prompt used by the local LLM to extract and redact personal info.</div>
          <div id="privacy-prompt-adv"></div>
        </div>

      </div>

      <div class="save-bar"><button class="btn btn-primary" onclick="savePrivacyRouter()" data-i18n="priv.save">Save Privacy Router</button></div>
    </div>
  </div>

  <!-- \u2550\u2550\u2550 Token-Saver Router Card \u2550\u2550\u2550 -->
  <div class="router-section">
    <div class="router-section-header" onclick="toggleSection(this)">
      <span class="section-arrow">&#9660;</span>
      <h3 data-i18n="co.title">Cost-Optimizer Router</h3>
      <span class="router-id-badge">token-saver</span>
    </div>
    <div class="router-section-body">
      <div class="hint" style="margin-bottom:14px" data-i18n="co.desc">Classifies task complexity and routes to the most cost-effective model.</div>

      <div class="field-toggle" style="margin-bottom:18px">
        <label data-i18n="common.enabled">Enabled</label>
        <label class="toggle"><input type="checkbox" id="cfg-ts-enabled"><span class="slider"></span></label>
      </div>

      <!-- Judge Model -->
      <div class="subsection">
        <h4 data-i18n-html="co.tier">Complexity Level &rarr; Model</h4>
        <div class="tier-grid">
          <div class="tier-grid-header" data-i18n="co.complexity">Complexity</div>
          <div class="tier-grid-header" data-i18n="co.provider">Provider</div>
          <div class="tier-grid-header" data-i18n="co.model">Model</div>
          <div class="tier-label">SIMPLE</div><input id="cfg-ts-tier-SIMPLE-provider" placeholder="openai"><input id="cfg-ts-tier-SIMPLE-model" placeholder="gpt-4o-mini">
          <div class="tier-label">MEDIUM</div><input id="cfg-ts-tier-MEDIUM-provider" placeholder="openai"><input id="cfg-ts-tier-MEDIUM-model" placeholder="gpt-4o">
          <div class="tier-label">COMPLEX</div><input id="cfg-ts-tier-COMPLEX-provider" placeholder="anthropic"><input id="cfg-ts-tier-COMPLEX-model" placeholder="claude-sonnet-4.6">
          <div class="tier-label">REASONING</div><input id="cfg-ts-tier-REASONING-provider" placeholder="openai"><input id="cfg-ts-tier-REASONING-model" placeholder="o4-mini">
        </div>
      </div>

      <!-- LLM Prompt (token-saver-specific) -->
      <div class="subsection">
        <h4 data-i18n="co.llm_prompt">LLM Prompt</h4>
        <div class="hint" style="margin-bottom:12px" data-i18n="co.llm_hint">Prompt used by the classifier LLM to determine task complexity.</div>
        <div id="tokensaver-prompt-editors"></div>
      </div>

      <!-- Per-router Test -->
      <div class="subsection">
        <h4 data-i18n="co.test_title">Test (Cost-Optimizer Only)</h4>
        <textarea class="test-input" id="test-token-saver-message" data-i18n-ph="co.test_ph" placeholder="Enter a message to test the cost-optimizer router alone..."></textarea>
        <div style="display:flex;gap:8px;margin-top:10px;align-items:center">
          <button class="btn btn-primary btn-sm" onclick="runRouterTest('token-saver')" data-i18n="co.test_btn">Test Cost-Optimizer</button>
        </div>
        <div class="test-result" id="test-token-saver-result">
          <div class="test-result-row"><span class="test-result-label" data-i18n="test.level">Level</span><span class="test-result-value" id="tr-token-saver-level">-</span></div>
          <div class="test-result-row"><span class="test-result-label" data-i18n="test.action">Action</span><span class="test-result-value" id="tr-token-saver-action">-</span></div>
          <div class="test-result-row"><span class="test-result-label" data-i18n="test.target">Target</span><span class="test-result-value" id="tr-token-saver-target">-</span></div>
          <div class="test-result-row"><span class="test-result-label" data-i18n="test.reason">Reason</span><span class="test-result-value" id="tr-token-saver-reason">-</span></div>
          <div class="test-result-row"><span class="test-result-label" data-i18n="test.confidence">Confidence</span><span class="test-result-value" id="tr-token-saver-confidence">-</span></div>
        </div>
        <div class="test-loading" id="test-token-saver-loading" style="display:none" data-i18n="test.testing">Testing...</div>
      </div>

      <!-- Advanced Configuration -->
      <div class="adv-toggle" onclick="toggleAdv(this)">
        <span class="adv-arrow">&#9654;</span> <span data-i18n="co.adv">Advanced Configuration</span>
      </div>
      <div class="adv-body">

        <!-- Cache Duration -->
        <div class="subsection">
          <h4 data-i18n="co.cache">Cache</h4>
          <div class="field">
            <label data-i18n="co.cache_dur">Cache Duration (ms)</label>
            <input id="cfg-ts-cachettl" type="number" placeholder="300000" style="max-width:180px">
          </div>
        </div>

      </div>

      <div class="save-bar"><button class="btn btn-primary" onclick="saveTokenSaverConfig()" data-i18n="co.save">Save Cost-Optimizer</button></div>
    </div>
  </div>

  <!-- \u2550\u2550\u2550 Custom Router Cards (rendered dynamically) \u2550\u2550\u2550 -->
  <div id="custom-router-cards"></div>

  <!-- Add Custom Router -->
  <div class="add-custom-router">
    <div style="display:flex;gap:10px;align-items:center">
      <input id="new-router-id" data-i18n-ph="cr.add_ph" placeholder="Router ID (e.g. content-filter)" style="flex:1;padding:10px 14px;background:var(--bg-input);border:1px solid transparent;border-radius:8px;color:var(--text-primary);font-size:13px;outline:none">
      <button class="btn btn-primary" onclick="addCustomRouter()" data-i18n="cr.add_btn">+ Add Custom Router</button>
    </div>
    <div class="hint" style="margin-top:8px" data-i18n="cr.add_hint">Create a new router with keyword rules and an optional LLM classification prompt. Added routers appear above and can be included in Router Execution Order.</div>
  </div>

</div>

<!-- Configuration -->
<div id="config-panel" class="panel">

  <div class="toggle-bar">
    <label data-i18n="cfg.enabled">GuardClaw Enabled</label>
    <label class="toggle"><input type="checkbox" id="cfg-enabled" checked><span class="slider"></span></label>
  </div>

  <div class="config-section">
    <h3><span data-i18n="preset.title">Quick Switch</span> <span class="badge badge-hot">instant</span></h3>
    <div class="hint" style="margin-bottom:14px" data-i18n="preset.desc">Switch between preconfigured LLM provider setups for Local Model and Guard Agent.</div>
    <div style="display:flex;gap:10px;align-items:flex-end">
      <div class="field" style="flex:1;margin-bottom:0">
        <select id="preset-select" onchange="onPresetSelectChange()"></select>
      </div>
      <button class="btn btn-primary btn-sm" onclick="applyPreset()" style="height:40px" data-i18n="preset.apply">Apply</button>
      <button class="btn btn-sm btn-outline" id="preset-delete-btn" onclick="deletePreset()" style="height:40px;display:none;color:#ef4444;border-color:#fca5a5" data-i18n="preset.delete">Delete</button>
    </div>
    <div id="preset-info" class="hint" style="display:none;margin-top:8px;color:var(--accent)"></div>
    <div style="display:flex;gap:10px;align-items:center;margin-top:12px">
      <input id="preset-save-name" data-i18n-ph="preset.name_ph" placeholder="New preset name..." style="flex:1;padding:10px 14px;background:var(--bg-input);border:1px solid transparent;border-radius:var(--radius-sm);color:var(--text-primary);font-size:13px;outline:none">
      <button class="btn btn-sm btn-outline" onclick="saveAsPreset()" data-i18n="preset.save_as">Save Current</button>
    </div>
  </div>

  <div class="config-section">
    <h3><span data-i18n="cfg.lm">Local Model</span> <span class="badge badge-hot">instant</span></h3>
    <div class="hint" style="margin-bottom:14px" data-i18n="cfg.lm_desc">Configure the LLM used locally for privacy classification and PII redaction.</div>
    <div class="field-toggle">
      <label data-i18n="cfg.lm_enabled">Enabled</label>
      <label class="toggle"><input type="checkbox" id="cfg-lm-enabled" checked><span class="slider"></span></label>
    </div>
    <div class="field">
      <label data-i18n="cfg.api_proto">API Protocol</label>
      <select id="cfg-lm-type">
        <option value="openai-compatible">openai-compatible (Ollama, vLLM, LMStudio ...)</option>
        <option value="ollama-native">ollama-native (Ollama /api/chat)</option>
        <option value="custom">custom (user module)</option>
      </select>
    </div>
    <div class="field"><label data-i18n="cfg.provider">Provider</label><input id="cfg-lm-provider" placeholder="ollama"></div>
    <div class="field"><label data-i18n="cfg.endpoint">Endpoint</label><input id="cfg-lm-endpoint" placeholder="http://localhost:11434"></div>
    <div class="field"><label data-i18n="cfg.model">Model</label><input id="cfg-lm-model" placeholder="openbmb/minicpm4.1"></div>
    <div class="field"><label data-i18n="cfg.api_key">API Key</label><input id="cfg-lm-apikey" type="password" placeholder="sk-..."></div>
    <div class="field" id="cfg-lm-module-wrap" style="display:none"><label data-i18n="cfg.custom_mod">Custom Module Path</label><input id="cfg-lm-module" placeholder="./my-provider.js"></div>
  </div>

  <div class="config-section">
    <h3><span data-i18n="cfg.cls">Cost-Optimizer Classifier</span> <span class="badge badge-hot">instant</span></h3>
    <div class="hint" style="margin-bottom:14px" data-i18n="cfg.cls_desc">LLM used by the Cost-Optimizer to determine task complexity. Falls back to the Local Model settings above if empty.</div>
    <div class="field"><label data-i18n="cfg.endpoint">Endpoint</label><input id="cfg-ts-endpoint" placeholder="(inherits from Local Model)"></div>
    <div class="field"><label data-i18n="cfg.model">Model</label><input id="cfg-ts-model" placeholder="(inherits from Local Model)"></div>
    <div class="field">
      <label data-i18n="cfg.api_proto">API Protocol</label>
      <select id="cfg-ts-providertype">
        <option value="openai-compatible">openai-compatible</option>
        <option value="ollama-native">ollama-native</option>
        <option value="custom">custom</option>
      </select>
    </div>
  </div>

  <div class="adv-toggle" onclick="toggleAdv(this)">
    <span class="adv-arrow">&#9654;</span> <span data-i18n="cfg.adv">Advanced Settings</span>
  </div>
  <div class="adv-body">

  <div class="config-section">
    <h3><span data-i18n="cfg.guard">Privacy Guard Agent</span> <span class="badge badge-hot">instant</span></h3>
    <div class="hint" style="margin-bottom:14px" data-i18n="cfg.guard_desc">A local agent that handles sensitive tasks entirely on-device.</div>
    <div class="field"><label data-i18n="cfg.agent_id">Agent ID</label><input id="cfg-ga-id" placeholder="guard"></div>
    <div class="field"><label data-i18n="cfg.workspace">Workspace</label><input id="cfg-ga-workspace" placeholder="~/.openclaw/workspace-guard"></div>
    <div class="field"><label data-i18n="cfg.model_prov">Model (provider/model)</label><input id="cfg-ga-model" placeholder="ollama/qwen3.5-27b"></div>
  </div>

  <div class="config-section">
    <h3><span data-i18n="cfg.routing">Routing Policy</span> <span class="badge badge-hot">instant</span></h3>
    <div class="hint" style="margin-bottom:14px" data-i18n="cfg.routing_desc">How S2-level sensitive data is handled before reaching the cloud.</div>
    <div class="field">
      <label data-i18n="cfg.sens_route">Sensitive Data Routing</label>
      <select id="cfg-s2policy">
        <option value="proxy" data-i18n-opt="cfg.s2_proxy">Proxy (redact personal info before sending)</option>
        <option value="local" data-i18n-opt="cfg.s2_local">Local only (process on-device, no cloud)</option>
      </select>
    </div>
    <div class="field">
      <label data-i18n="cfg.proxy_port">Proxy Port</label>
      <input id="cfg-proxyport" type="number" placeholder="8403" style="max-width:160px">
      <div class="hint" data-i18n="cfg.restart_hint">Requires restart to take effect</div>
    </div>
  </div>

  <div class="config-section">
    <h3><span data-i18n="cfg.session">Session Settings</span> <span class="badge badge-hot">instant</span></h3>
    <div class="hint" style="margin-bottom:14px" data-i18n="cfg.session_desc">Manage isolation and storage of guard-related session data.</div>
    <div class="field-toggle">
      <label data-i18n="cfg.isolate">Separate Guard Chat History</label>
      <label class="toggle"><input type="checkbox" id="cfg-sess-isolate" checked><span class="slider"></span></label>
    </div>
    <div class="field"><label data-i18n="cfg.base_dir">Base Directory</label><input id="cfg-sess-basedir" placeholder="~/.openclaw"></div>
  </div>

  <div class="config-section">
    <h3><span data-i18n="cfg.redaction">Rule-based Redaction</span> <span class="badge badge-hot">instant</span></h3>
    <div class="hint" style="margin-bottom:14px" data-i18n="cfg.redaction_desc">Toggle individual PII pattern rules. Off by default to reduce false positives.</div>
    <div class="field-toggle"><label data-i18n="cfg.rd_ip">Internal IP Addresses (10.x, 172.x, 192.168.x)</label><label class="toggle"><input type="checkbox" id="cfg-rd-internalIp"><span class="slider"></span></label></div>
    <div class="field-toggle"><label data-i18n="cfg.rd_email">Email Addresses</label><label class="toggle"><input type="checkbox" id="cfg-rd-email"><span class="slider"></span></label></div>
    <div class="field-toggle"><label data-i18n="cfg.rd_env">Environment Variables (.env KEY=VALUE)</label><label class="toggle"><input type="checkbox" id="cfg-rd-envVar"><span class="slider"></span></label></div>
    <div class="field-toggle"><label data-i18n="cfg.rd_card">Credit Card Numbers (13-19 digits)</label><label class="toggle"><input type="checkbox" id="cfg-rd-creditCard"><span class="slider"></span></label></div>
    <div class="field-toggle"><label data-i18n="cfg.rd_phone">Chinese Mobile Phone (1[3-9]x)</label><label class="toggle"><input type="checkbox" id="cfg-rd-chinesePhone"><span class="slider"></span></label></div>
    <div class="field-toggle"><label data-i18n="cfg.rd_id">Chinese ID Card (18 digits)</label><label class="toggle"><input type="checkbox" id="cfg-rd-chineseId"><span class="slider"></span></label></div>
    <div class="field-toggle"><label data-i18n="cfg.rd_addr">Chinese Addresses</label><label class="toggle"><input type="checkbox" id="cfg-rd-chineseAddress"><span class="slider"></span></label></div>
    <div class="field-toggle"><label data-i18n="cfg.rd_pin">PIN / Pin Code</label><label class="toggle"><input type="checkbox" id="cfg-rd-pin"><span class="slider"></span></label></div>
  </div>

  <div class="config-section">
    <h3><span data-i18n="cfg.local_prov">Local Providers</span> <span class="badge badge-hot">instant</span></h3>
    <div class="field">
      <label data-i18n="cfg.local_prov_hint">Additional providers treated as &quot;local&quot; (safe for confidential data routing)</label>
      <div class="tag-list" id="cfg-tags-lp"></div>
      <div class="add-row">
        <input id="cfg-tags-lp-input" placeholder="e.g. my-inference-server" onkeydown="if(event.key==='Enter'){event.preventDefault();addTag('lp')}">
        <button class="btn btn-sm btn-outline" onclick="addTag('lp')">Add</button>
      </div>
    </div>
  </div>

  </div>

  <div class="config-section">
    <h3><span data-i18n="cfg.pricing">Model Pricing</span> <span class="badge badge-hot">instant</span></h3>
    <div class="hint" style="margin-bottom:14px" data-i18n="cfg.pricing_desc">Configure per-model pricing for cloud API cost estimation (USD per 1M tokens). Only cloud models are tracked.</div>
    <table class="data-table" id="pricing-table">
      <thead><tr><th data-i18n="cfg.pricing_model">Model</th><th data-i18n="cfg.pricing_input">Input $/1M</th><th data-i18n="cfg.pricing_output">Output $/1M</th><th style="width:40px"></th></tr></thead>
      <tbody id="pricing-body"></tbody>
    </table>
    <div class="add-row" style="margin-top:12px">
      <input id="pricing-new-model" placeholder="e.g. gpt-4o" style="flex:2;padding:10px 14px;background:var(--bg-input);border:1px solid transparent;border-radius:var(--radius-sm);color:var(--text-primary);font-size:13px;outline:none">
      <input id="pricing-new-input" type="number" step="0.01" placeholder="Input $/1M" style="flex:1;padding:10px 14px;background:var(--bg-input);border:1px solid transparent;border-radius:var(--radius-sm);color:var(--text-primary);font-size:13px;outline:none">
      <input id="pricing-new-output" type="number" step="0.01" placeholder="Output $/1M" style="flex:1;padding:10px 14px;background:var(--bg-input);border:1px solid transparent;border-radius:var(--radius-sm);color:var(--text-primary);font-size:13px;outline:none">
      <button class="btn btn-sm btn-outline" onclick="addPricingRow()" data-i18n="cfg.pricing_add">Add Model</button>
    </div>
    <div style="margin-top:10px">
      <button class="btn btn-sm btn-outline" onclick="loadDefaultPricing()" data-i18n="cfg.pricing_load">Load Defaults</button>
    </div>
  </div>

  <div class="save-bar">
    <button class="btn btn-primary" onclick="saveConfig()" data-i18n="cfg.save">Save Configuration</button>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
var BASE = '/plugins/guardclaw/stats/api';
var hourlyChart = null;
var _detections = [];
var _detectionFilter = 'all';

// \u2500\u2500 i18n \u2500\u2500
var LANG = localStorage.getItem('gc-lang') || 'en';
var T = {
  'tab.overview':{en:'Overview',zh:'\u6982\u89C8'},
  'tab.sessions':{en:'Sessions',zh:'\u4F1A\u8BDD'},
  'tab.detections':{en:'Detection Log',zh:'\u68C0\u6D4B\u65E5\u5FD7'},
  'tab.rules':{en:'Router Rules',zh:'\u8DEF\u7531\u89C4\u5219'},
  'tab.config':{en:'Configuration',zh:'\u914D\u7F6E'},
  'header.title':{en:'GuardClaw Dashboard',zh:'GuardClaw \u63A7\u5236\u53F0'},
  'header.connecting':{en:'Connecting...',zh:'\u8FDE\u63A5\u4E2D...'},
  'header.refresh':{en:'Refresh',zh:'\u5237\u65B0'},
  'header.online':{en:'Online',zh:'\u5728\u7EBF'},
  'overview.cloud':{en:'Cloud Tokens',zh:'\u4E91\u7AEF Tokens'},
  'overview.local':{en:'Local Tokens',zh:'\u672C\u5730 Tokens'},
  'overview.redacted':{en:'Redacted Tokens',zh:'\u8131\u654F Tokens'},
  'overview.protection':{en:'Data Protection Rate',zh:'\u6570\u636E\u4FDD\u62A4\u7387'},
  'overview.cost':{en:'Cloud Cost',zh:'\u4E91\u7AEF\u8D39\u7528'},
  'overview.cost_sub':{en:'estimated cloud API cost',zh:'\u4F30\u7B97\u4E91\u7AEF API \u8D39\u7528'},
  'overview.sub':{en:'of total tokens protected',zh:'\u53D7\u4FDD\u62A4\u7684 Token \u5360\u6BD4'},
  'overview.chart':{en:'Hourly Token Usage',zh:'\u6BCF\u5C0F\u65F6 Token \u7528\u91CF'},
  'overview.requests':{en:'requests',zh:'\u8BF7\u6C42'},
  'overview.no_data':{en:'No data yet',zh:'\u6682\u65E0\u6570\u636E'},
  'overview.reset_btn':{en:'Reset Stats',zh:'\u91CD\u7F6E\u7EDF\u8BA1'},
  'overview.reset_confirm':{en:'Reset all token statistics? This cannot be undone.',zh:'\u786E\u5B9A\u8981\u91CD\u7F6E\u6240\u6709 Token \u7EDF\u8BA1\u6570\u636E\u5417\uFF1F\u6B64\u64CD\u4F5C\u4E0D\u53EF\u64A4\u9500\u3002'},
  'overview.reset_ok':{en:'Stats reset successfully',zh:'\u7EDF\u8BA1\u6570\u636E\u5DF2\u91CD\u7F6E'},
  'overview.reset_fail':{en:'Failed to reset stats: ',zh:'\u91CD\u7F6E\u7EDF\u8BA1\u5931\u8D25\uFF1A'},
  'table.category':{en:'Category',zh:'\u5206\u7C7B'},
  'table.input':{en:'Input',zh:'\u8F93\u5165'},
  'table.output':{en:'Output',zh:'\u8F93\u51FA'},
  'table.cache':{en:'Cache Read',zh:'\u7F13\u5B58\u8BFB\u53D6'},
  'table.total':{en:'Total',zh:'\u603B\u8BA1'},
  'table.requests':{en:'Requests',zh:'\u8BF7\u6C42\u6570'},
  'table.cost':{en:'Cost',zh:'\u8D39\u7528'},
  'table.by_source':{en:'By Source (Router vs Task)',zh:'\u6309\u6765\u6E90\uFF08\u8DEF\u7531\u5F00\u9500 vs \u4EFB\u52A1\u6267\u884C\uFF09'},
  'table.source':{en:'Source',zh:'\u6765\u6E90'},
  'sessions.session':{en:'Session',zh:'\u4F1A\u8BDD'},
  'sessions.level':{en:'Level',zh:'\u7B49\u7EA7'},
  'sessions.cloud':{en:'Cloud',zh:'\u4E91\u7AEF'},
  'sessions.local':{en:'Local',zh:'\u672C\u5730'},
  'sessions.redacted':{en:'Redacted',zh:'\u8131\u654F'},
  'sessions.cost':{en:'Cost',zh:'\u8D39\u7528'},
  'sessions.total':{en:'Total',zh:'\u603B\u8BA1'},
  'sessions.requests':{en:'Requests',zh:'\u8BF7\u6C42\u6570'},
  'sessions.last_active':{en:'Last Active',zh:'\u6700\u8FD1\u6D3B\u8DC3'},
  'sessions.empty':{en:'No session data yet',zh:'\u6682\u65E0\u4F1A\u8BDD\u6570\u636E'},
  'det.time':{en:'Time',zh:'\u65F6\u95F4'},
  'det.session':{en:'Session',zh:'\u4F1A\u8BDD'},
  'det.level':{en:'Level',zh:'\u7B49\u7EA7'},
  'det.checkpoint':{en:'Checkpoint',zh:'\u68C0\u67E5\u70B9'},
  'det.reason':{en:'Reason',zh:'\u539F\u56E0'},
  'det.empty':{en:'No detections yet',zh:'\u6682\u65E0\u68C0\u6D4B\u8BB0\u5F55'},
  'det.empty_for':{en:'No detections for ',zh:'\u6682\u65E0\u68C0\u6D4B\u8BB0\u5F55\uFF1A'},
  'det.all':{en:'All',zh:'\u5168\u90E8'},
  'test.title':{en:'Test Classification',zh:'\u5206\u7C7B\u6D4B\u8BD5'},
  'test.hint':{en:'Test how the router pipeline would classify a message (no changes applied).',zh:'\u6D4B\u8BD5\u8DEF\u7531\u7BA1\u9053\u5982\u4F55\u5BF9\u6D88\u606F\u8FDB\u884C\u5206\u7C7B\uFF08\u4E0D\u4F1A\u5B9E\u9645\u751F\u6548\uFF09\u3002'},
  'test.placeholder':{en:'e.g. "\u5E2E\u6211\u5206\u6790\u4E00\u4E0B\u8FD9\u4E2A\u6708\u7684\u5DE5\u8D44\u5355" or "write a poem about spring"',zh:'\u4F8B\u5982 "\u5E2E\u6211\u5206\u6790\u4E00\u4E0B\u8FD9\u4E2A\u6708\u7684\u5DE5\u8D44\u5355" \u6216 "write a poem about spring"'},
  'test.run':{en:'Run Test',zh:'\u8FD0\u884C\u6D4B\u8BD5'},
  'test.merged':{en:'Merged Result',zh:'\u5408\u5E76\u7ED3\u679C'},
  'test.level':{en:'Level',zh:'\u7B49\u7EA7'},
  'test.action':{en:'Action',zh:'\u52A8\u4F5C'},
  'test.target':{en:'Target',zh:'\u76EE\u6807'},
  'test.deciding':{en:'Deciding Router',zh:'\u51B3\u7B56\u8DEF\u7531'},
  'test.reason':{en:'Reason',zh:'\u539F\u56E0'},
  'test.confidence':{en:'Confidence',zh:'\u7F6E\u4FE1\u5EA6'},
  'test.classifying':{en:'Classifying...',zh:'\u5206\u7C7B\u4E2D...'},
  'test.testing':{en:'Testing...',zh:'\u6D4B\u8BD5\u4E2D...'},
  'test.individual':{en:'Individual Router Results',zh:'\u5404\u8DEF\u7531\u72EC\u7ACB\u7ED3\u679C'},
  'test.enter_msg':{en:'Enter a test message',zh:'\u8BF7\u8F93\u5165\u6D4B\u8BD5\u6D88\u606F'},
  'test.failed':{en:'Test failed: ',zh:'\u6D4B\u8BD5\u5931\u8D25\uFF1A'},
  'ck.user_message':{en:'User Message',zh:'\u7528\u6237\u6D88\u606F'},
  'ck.before_tool':{en:'Before Tool Runs',zh:'\u5DE5\u5177\u6267\u884C\u524D'},
  'ck.after_tool':{en:'After Tool Runs',zh:'\u5DE5\u5177\u6267\u884C\u540E'},
  'pipe.title':{en:'Router Execution Order (Advanced)',zh:'\u8DEF\u7531\u6267\u884C\u987A\u5E8F\uFF08\u9AD8\u7EA7\uFF09'},
  'pipe.hint':{en:'Click a router to add it to a stage. Drag tags to reorder. Click \\u00d7 to remove.',zh:'\u70B9\u51FB\u8DEF\u7531\u6DFB\u52A0\u5230\u5BF9\u5E94\u9636\u6BB5\u3002\u62D6\u62FD\u6807\u7B7E\u8C03\u6574\u987A\u5E8F\uFF0C\u70B9\u51FB \\u00d7 \u79FB\u9664\u3002'},
  'pipe.save':{en:'Save Execution Order',zh:'\u4FDD\u5B58\u6267\u884C\u987A\u5E8F'},
  'pipe.saved':{en:'Execution order saved',zh:'\u6267\u884C\u987A\u5E8F\u5DF2\u4FDD\u5B58'},
  'priv.title':{en:'Privacy Router',zh:'\u9690\u79C1\u8DEF\u7531'},
  'priv.desc':{en:'Detects sensitive data in messages and routes to local or redacted cloud models.',zh:'\u68C0\u6D4B\u6D88\u606F\u4E2D\u7684\u654F\u611F\u6570\u636E\uFF0C\u8DEF\u7531\u5230\u672C\u5730\u6A21\u578B\u6216\u8131\u654F\u540E\u53D1\u9001\u4E91\u7AEF\u3002'},
  'priv.keywords':{en:'Keywords',zh:'\u5173\u952E\u8BCD'},
  'priv.s2':{en:'S2 \\u2014 Sensitive (Redact \\u2192 Cloud)',zh:'S2 \\u2014 \u654F\u611F\uFF08\u8131\u654F\u540E\u8D70\u4E91\u7AEF\uFF09'},
  'priv.s3':{en:'S3 \\u2014 Confidential (Local Model Only)',zh:'S3 \\u2014 \u673A\u5BC6\uFF08\u4EC5\u672C\u5730\u6A21\u578B\uFF09'},
  'priv.llm_prompt':{en:'LLM Prompt',zh:'LLM \u63D0\u793A\u8BCD'},
  'priv.llm_hint':{en:'Prompt used by the local LLM to classify data sensitivity (S1/S2/S3).',zh:'\u672C\u5730 LLM \u7528\u4E8E\u5206\u7C7B\u6570\u636E\u654F\u611F\u7B49\u7EA7\uFF08S1/S2/S3\uFF09\u7684\u63D0\u793A\u8BCD\u3002'},
  'priv.test_title':{en:'Test (Privacy Router Only)',zh:'\u6D4B\u8BD5\uFF08\u4EC5\u9690\u79C1\u8DEF\u7531\uFF09'},
  'priv.test_ph':{en:'Enter a message to test the privacy router alone...',zh:'\u8F93\u5165\u6D88\u606F\u4EE5\u5355\u72EC\u6D4B\u8BD5\u9690\u79C1\u8DEF\u7531...'},
  'priv.test_btn':{en:'Test Privacy Router',zh:'\u6D4B\u8BD5\u9690\u79C1\u8DEF\u7531'},
  'priv.save':{en:'Save Privacy Router',zh:'\u4FDD\u5B58\u9690\u79C1\u8DEF\u7531'},
  'priv.saved':{en:'Privacy Router saved',zh:'\u9690\u79C1\u8DEF\u7531\u5DF2\u4FDD\u5B58'},
  'priv.adv':{en:'Advanced Configuration',zh:'\u9AD8\u7EA7\u914D\u7F6E'},
  'priv.when':{en:'When to Run',zh:'\u4F55\u65F6\u8FD0\u884C'},
  'priv.when_hint':{en:'Select which detectors run at each stage for the privacy router.',zh:'\u9009\u62E9\u9690\u79C1\u8DEF\u7531\u5728\u6BCF\u4E2A\u9636\u6BB5\u8FD0\u884C\u7684\u68C0\u6D4B\u5668\u3002'},
  'priv.kw_regex':{en:'Keyword \\u0026 Regex',zh:'\u5173\u952E\u8BCD\u548C\u6B63\u5219'},
  'priv.llm_cls':{en:'LLM Classifier',zh:'LLM \u5206\u7C7B\u5668'},
  'priv.det_rules':{en:'Detection Rules (Regex \\u0026 Tool Filters)',zh:'\u68C0\u6D4B\u89C4\u5219\uFF08\u6B63\u5219\u548C\u5DE5\u5177\u8FC7\u6EE4\uFF09'},
  'priv.regex':{en:'Regex Patterns',zh:'\u6B63\u5219\u8868\u8FBE\u5F0F'},
  'priv.tools':{en:'Sensitive Tool Names',zh:'\u654F\u611F\u5DE5\u5177\u540D'},
  'priv.paths':{en:'Sensitive File Paths',zh:'\u654F\u611F\u6587\u4EF6\u8DEF\u5F84'},
  'priv.pii':{en:'Personal Info Redaction Prompt',zh:'\u4E2A\u4EBA\u4FE1\u606F\u8131\u654F\u63D0\u793A\u8BCD'},
  'priv.pii_hint':{en:'Prompt used by the local LLM to extract and redact personal info.',zh:'\u672C\u5730 LLM \u7528\u4E8E\u63D0\u53D6\u548C\u8131\u654F\u4E2A\u4EBA\u4FE1\u606F\u7684\u63D0\u793A\u8BCD\u3002'},
  'co.title':{en:'Cost-Optimizer Router',zh:'\u6210\u672C\u4F18\u5316\u8DEF\u7531'},
  'co.desc':{en:'Classifies task complexity and routes to the most cost-effective model.',zh:'\u5224\u65AD\u4EFB\u52A1\u590D\u6742\u5EA6\uFF0C\u81EA\u52A8\u9009\u62E9\u6027\u4EF7\u6BD4\u6700\u9AD8\u7684\u6A21\u578B\u3002'},
  'co.tier':{en:'Complexity Level \\u2192 Model',zh:'\u590D\u6742\u5EA6\u7B49\u7EA7 \\u2192 \u6A21\u578B'},
  'co.complexity':{en:'Complexity',zh:'\u590D\u6742\u5EA6'},
  'co.provider':{en:'Provider',zh:'\u4F9B\u5E94\u5546'},
  'co.model':{en:'Model',zh:'\u6A21\u578B'},
  'co.llm_prompt':{en:'LLM Prompt',zh:'LLM \u63D0\u793A\u8BCD'},
  'co.llm_hint':{en:'Prompt used by the classifier LLM to determine task complexity.',zh:'\u5206\u7C7B LLM \u7528\u4E8E\u5224\u65AD\u4EFB\u52A1\u590D\u6742\u5EA6\u7684\u63D0\u793A\u8BCD\u3002'},
  'co.test_title':{en:'Test (Cost-Optimizer Only)',zh:'\u6D4B\u8BD5\uFF08\u4EC5\u6210\u672C\u4F18\u5316\uFF09'},
  'co.test_ph':{en:'Enter a message to test the cost-optimizer router alone...',zh:'\u8F93\u5165\u6D88\u606F\u4EE5\u5355\u72EC\u6D4B\u8BD5\u6210\u672C\u4F18\u5316\u8DEF\u7531...'},
  'co.test_btn':{en:'Test Cost-Optimizer',zh:'\u6D4B\u8BD5\u6210\u672C\u4F18\u5316'},
  'co.save':{en:'Save Cost-Optimizer',zh:'\u4FDD\u5B58\u6210\u672C\u4F18\u5316'},
  'co.saved':{en:'Cost-Optimizer config saved',zh:'\u6210\u672C\u4F18\u5316\u914D\u7F6E\u5DF2\u4FDD\u5B58'},
  'co.adv':{en:'Advanced Configuration',zh:'\u9AD8\u7EA7\u914D\u7F6E'},
  'co.cache':{en:'Cache',zh:'\u7F13\u5B58'},
  'co.cache_dur':{en:'Cache Duration (ms)',zh:'\u7F13\u5B58\u65F6\u957F\uFF08\u6BEB\u79D2\uFF09'},
  'cr.add_ph':{en:'Router ID (e.g. content-filter)',zh:'\u8DEF\u7531 ID\uFF08\u5982 content-filter\uFF09'},
  'cr.add_btn':{en:'+ Add Custom Router',zh:'+ \u6DFB\u52A0\u81EA\u5B9A\u4E49\u8DEF\u7531'},
  'cr.add_hint':{en:'Create a new router with keyword rules and an optional LLM classification prompt. Added routers appear above and can be included in Router Execution Order.',zh:'\u521B\u5EFA\u4E00\u4E2A\u5E26\u6709\u5173\u952E\u8BCD\u89C4\u5219\u548C\u53EF\u9009 LLM \u5206\u7C7B\u63D0\u793A\u8BCD\u7684\u65B0\u8DEF\u7531\u3002\u6DFB\u52A0\u540E\u663E\u793A\u5728\u4E0A\u65B9\uFF0C\u53EF\u52A0\u5165\u8DEF\u7531\u6267\u884C\u987A\u5E8F\u3002'},
  'cr.kw_rules':{en:'Keyword Rules',zh:'\u5173\u952E\u8BCD\u89C4\u5219'},
  'cr.s2_kw':{en:'S2 \\u2014 Sensitive Keywords',zh:'S2 \\u2014 \u654F\u611F\u5173\u952E\u8BCD'},
  'cr.s3_kw':{en:'S3 \\u2014 Confidential Keywords',zh:'S3 \\u2014 \u673A\u5BC6\u5173\u952E\u8BCD'},
  'cr.s2_pat':{en:'S2 \\u2014 Sensitive Patterns (regex)',zh:'S2 \\u2014 \u654F\u611F\u6A21\u5F0F\uFF08\u6B63\u5219\uFF09'},
  'cr.s3_pat':{en:'S3 \\u2014 Confidential Patterns (regex)',zh:'S3 \\u2014 \u673A\u5BC6\u6A21\u5F0F\uFF08\u6B63\u5219\uFF09'},
  'cr.cls_prompt':{en:'Classification Prompt',zh:'\u5206\u7C7B\u63D0\u793A\u8BCD'},
  'cr.cls_hint':{en:'If set, the local LLM will classify messages using this prompt. Should output JSON with {level, reason}.',zh:'\u5982\u679C\u8BBE\u7F6E\uFF0C\u672C\u5730 LLM \u5C06\u4F7F\u7528\u6B64\u63D0\u793A\u8BCD\u5206\u7C7B\u6D88\u606F\u3002\u5E94\u8F93\u51FA\u5305\u542B {level, reason} \u7684 JSON\u3002'},
  'cr.enter_id':{en:'Enter a router ID',zh:'\u8BF7\u8F93\u5165\u8DEF\u7531 ID'},
  'cr.exists':{en:'" already exists',zh:'" \u5DF2\u5B58\u5728'},
  'cr.created':{en:'" created \\u2014 configure and save it below',zh:'" \u5DF2\u521B\u5EFA \\u2014 \u8BF7\u5728\u4E0B\u65B9\u914D\u7F6E\u5E76\u4FDD\u5B58'},
  'cr.del_pre':{en:'Delete router "',zh:'\u786E\u8BA4\u5220\u9664\u8DEF\u7531 "'},
  'cr.del_suf':{en:'"? This cannot be undone.',zh:'"\uFF1F\u6B64\u64CD\u4F5C\u4E0D\u53EF\u64A4\u9500\u3002'},
  'cr.deleted':{en:'" deleted',zh:'" \u5DF2\u5220\u9664'},
  'cr.saved':{en:'" saved',zh:'" \u5DF2\u4FDD\u5B58'},
  'cfg.enabled':{en:'GuardClaw Enabled',zh:'GuardClaw \u542F\u7528'},
  'cfg.lm':{en:'Local Model',zh:'\u672C\u5730\u6A21\u578B'},
  'cfg.lm_desc':{en:'Configure the LLM used locally for privacy classification and PII redaction.',zh:'\u914D\u7F6E\u7528\u4E8E\u9690\u79C1\u5206\u7C7B\u548C\u4E2A\u4EBA\u4FE1\u606F\u8131\u654F\u7684\u672C\u5730 LLM\u3002'},
  'cfg.lm_enabled':{en:'Enabled',zh:'\u542F\u7528'},
  'cfg.api_proto':{en:'API Protocol',zh:'API \u534F\u8BAE'},
  'cfg.provider':{en:'Provider',zh:'\u4F9B\u5E94\u5546'},
  'cfg.endpoint':{en:'Endpoint',zh:'\u7AEF\u70B9'},
  'cfg.model':{en:'Model',zh:'\u6A21\u578B'},
  'cfg.api_key':{en:'API Key',zh:'API \u5BC6\u94A5'},
  'cfg.custom_mod':{en:'Custom Module Path',zh:'\u81EA\u5B9A\u4E49\u6A21\u5757\u8DEF\u5F84'},
  'cfg.cls':{en:'Cost-Optimizer Classifier',zh:'\u6210\u672C\u4F18\u5316\u5206\u7C7B\u5668'},
  'cfg.cls_desc':{en:'LLM used by the Cost-Optimizer to determine task complexity. Falls back to the Local Model settings above if empty.',zh:'\u6210\u672C\u4F18\u5316\u8DEF\u7531\u7528\u4E8E\u5224\u65AD\u4EFB\u52A1\u590D\u6742\u5EA6\u7684 LLM\u3002\u7559\u7A7A\u5219\u4F7F\u7528\u4E0A\u65B9\u672C\u5730\u6A21\u578B\u914D\u7F6E\u3002'},
  'cfg.adv':{en:'Advanced Settings',zh:'\u9AD8\u7EA7\u8BBE\u7F6E'},
  'cfg.guard':{en:'Privacy Guard Agent',zh:'\u9690\u79C1\u5B88\u62A4 Agent'},
  'cfg.guard_desc':{en:'A local agent that handles sensitive tasks entirely on-device.',zh:'\u5B8C\u5168\u5728\u672C\u5730\u8FD0\u884C\u7684\u9690\u79C1\u5B88\u62A4 Agent\u3002'},
  'cfg.agent_id':{en:'Agent ID',zh:'Agent ID'},
  'cfg.workspace':{en:'Workspace',zh:'\u5DE5\u4F5C\u76EE\u5F55'},
  'cfg.model_prov':{en:'Model (provider/model)',zh:'\u6A21\u578B\uFF08\u4F9B\u5E94\u5546/\u6A21\u578B\uFF09'},
  'cfg.routing':{en:'Routing Policy',zh:'\u8DEF\u7531\u7B56\u7565'},
  'cfg.routing_desc':{en:'How S2-level sensitive data is handled before reaching the cloud.',zh:'S2 \u7EA7\u654F\u611F\u6570\u636E\u53D1\u9001\u4E91\u7AEF\u524D\u7684\u5904\u7406\u7B56\u7565\u3002'},
  'cfg.sens_route':{en:'Sensitive Data Routing',zh:'\u654F\u611F\u6570\u636E\u8DEF\u7531'},
  'cfg.s2_proxy':{en:'Proxy (redact personal info before sending)',zh:'\u4EE3\u7406\uFF08\u53D1\u9001\u524D\u8131\u654F\u4E2A\u4EBA\u4FE1\u606F\uFF09'},
  'cfg.s2_local':{en:'Local only (process on-device, no cloud)',zh:'\u4EC5\u672C\u5730\uFF08\u8BBE\u5907\u7AEF\u5904\u7406\uFF0C\u4E0D\u4E0A\u4E91\uFF09'},
  'cfg.proxy_port':{en:'Proxy Port',zh:'\u4EE3\u7406\u7AEF\u53E3'},
  'cfg.restart_hint':{en:'Requires restart to take effect',zh:'\u9700\u8981\u91CD\u542F\u751F\u6548'},
  'cfg.session':{en:'Session Settings',zh:'\u4F1A\u8BDD\u8BBE\u7F6E'},
  'cfg.session_desc':{en:'Manage isolation and storage of guard-related session data.',zh:'\u7BA1\u7406\u9694\u79BB\u4E0E\u5B58\u50A8\u5B88\u62A4\u76F8\u5173\u7684\u4F1A\u8BDD\u6570\u636E\u3002'},
  'cfg.isolate':{en:'Separate Guard Chat History',zh:'\u9694\u79BB\u5B88\u62A4\u804A\u5929\u8BB0\u5F55'},
  'cfg.base_dir':{en:'Base Directory',zh:'\u57FA\u7840\u76EE\u5F55'},
  'cfg.local_prov':{en:'Local Providers',zh:'\u672C\u5730\u4F9B\u5E94\u5546'},
  'cfg.local_prov_hint':{en:'Additional providers treated as "local" (safe for confidential data routing)',zh:'\u989D\u5916\u89C6\u4E3A"\u672C\u5730"\u7684\u4F9B\u5E94\u5546\uFF08\u53EF\u5B89\u5168\u8DEF\u7531\u673A\u5BC6\u6570\u636E\uFF09'},
  'cfg.pricing':{en:'Model Pricing',zh:'\u6A21\u578B\u5B9A\u4EF7'},
  'cfg.pricing_desc':{en:'Configure per-model pricing for cloud API cost estimation (USD per 1M tokens). Only cloud models are tracked.',zh:'\u914D\u7F6E\u4E91\u7AEF\u6A21\u578B\u7684\u5355\u4EF7\u7528\u4E8E\u8D39\u7528\u4F30\u7B97\uFF08\u7F8E\u5143/\u767E\u4E07 Token\uFF09\u3002\u4EC5\u7EDF\u8BA1\u4E91\u7AEF\u6A21\u578B\u3002'},
  'cfg.pricing_model':{en:'Model',zh:'\u6A21\u578B'},
  'cfg.pricing_input':{en:'Input $/1M',zh:'\u8F93\u5165 $/1M'},
  'cfg.pricing_output':{en:'Output $/1M',zh:'\u8F93\u51FA $/1M'},
  'cfg.pricing_add':{en:'Add Model',zh:'\u6DFB\u52A0\u6A21\u578B'},
  'cfg.pricing_load':{en:'Load Defaults',zh:'\u52A0\u8F7D\u9ED8\u8BA4'},
  'cfg.redaction':{en:'Rule-based Redaction',zh:'\u89C4\u5219\u8131\u654F'},
  'cfg.redaction_desc':{en:'Toggle individual PII pattern rules. Off by default to reduce false positives.',zh:'\u63A7\u5236\u5404\u6761 PII \u6B63\u5219\u89C4\u5219\u7684\u542F\u505C\uFF0C\u9ED8\u8BA4\u5173\u95ED\u4EE5\u51CF\u5C11\u8BEF\u62A5\u3002'},
  'cfg.rd_ip':{en:'Internal IP Addresses (10.x, 172.x, 192.168.x)',zh:'\u5185\u7F51 IP \u5730\u5740 (10.x, 172.x, 192.168.x)'},
  'cfg.rd_email':{en:'Email Addresses',zh:'\u7535\u5B50\u90AE\u7BB1'},
  'cfg.rd_env':{en:'Environment Variables (.env KEY=VALUE)',zh:'\u73AF\u5883\u53D8\u91CF (.env KEY=VALUE)'},
  'cfg.rd_card':{en:'Credit Card Numbers (13-19 digits)',zh:'\u4FE1\u7528\u5361\u53F7 (13-19 \u4F4D)'},
  'cfg.rd_phone':{en:'Chinese Mobile Phone (1[3-9]x)',zh:'\u4E2D\u56FD\u624B\u673A\u53F7 (1[3-9]x)'},
  'cfg.rd_id':{en:'Chinese ID Card (18 digits)',zh:'\u4E2D\u56FD\u8EAB\u4EFD\u8BC1 (18 \u4F4D)'},
  'cfg.rd_addr':{en:'Chinese Addresses',zh:'\u4E2D\u56FD\u5730\u5740'},
  'cfg.rd_pin':{en:'PIN / Pin Code',zh:'PIN \u7801'},
  'cfg.save':{en:'Save Configuration',zh:'\u4FDD\u5B58\u914D\u7F6E'},
  'cfg.saved':{en:'Configuration saved',zh:'\u914D\u7F6E\u5DF2\u4FDD\u5B58'},
  'preset.title':{en:'Quick Switch',zh:'\u5FEB\u901F\u5207\u6362'},
  'preset.desc':{en:'Switch between preconfigured LLM provider setups for Local Model and Guard Agent.',zh:'\u5728\u9884\u914D\u7F6E\u7684 LLM \u4F9B\u5E94\u5546\u7EC4\u5408\u4E4B\u95F4\u5FEB\u901F\u5207\u6362\uFF08\u672C\u5730\u6A21\u578B + \u5B88\u62A4 Agent\uFF09\u3002'},
  'preset.apply':{en:'Apply',zh:'\u5E94\u7528'},
  'preset.delete':{en:'Delete',zh:'\u5220\u9664'},
  'preset.save_as':{en:'Save Current',zh:'\u4FDD\u5B58\u5F53\u524D'},
  'preset.name_ph':{en:'New preset name...',zh:'\u65B0\u9884\u8BBE\u540D\u79F0...'},
  'preset.select_ph':{en:'-- Select a preset --',zh:'-- \u9009\u62E9\u9884\u8BBE --'},
  'preset.select_first':{en:'Please select a preset first',zh:'\u8BF7\u5148\u9009\u62E9\u4E00\u4E2A\u9884\u8BBE'},
  'preset.applied':{en:'Preset applied',zh:'\u9884\u8BBE\u5DF2\u5E94\u7528'},
  'preset.saved':{en:'Preset saved',zh:'\u9884\u8BBE\u5DF2\u4FDD\u5B58'},
  'preset.deleted':{en:'Preset deleted',zh:'\u9884\u8BBE\u5DF2\u5220\u9664'},
  'preset.delete_confirm':{en:'Delete this custom preset?',zh:'\u786E\u5B9A\u8981\u5220\u9664\u8FD9\u4E2A\u81EA\u5B9A\u4E49\u9884\u8BBE\u5417\uFF1F'},
  'preset.name_required':{en:'Please enter a preset name',zh:'\u8BF7\u8F93\u5165\u9884\u8BBE\u540D\u79F0'},
  'preset.builtin':{en:'Built-in',zh:'\u5185\u7F6E'},
  'preset.custom':{en:'Custom',zh:'\u81EA\u5B9A\u4E49'},
  'preset.includes_default':{en:'Default model: ',zh:'\u9ED8\u8BA4\u6A21\u578B\uFF1A'},
  'preset.confirm_default_1':{en:'This preset will also change the default model to ',zh:'\u6B64\u9884\u8BBE\u8FD8\u5C06\u628A\u9ED8\u8BA4\u6A21\u578B\u5207\u6362\u4E3A '},
  'preset.confirm_default_2':{en:'. This requires a gateway restart. Apply default model change?',zh:'\u3002\u6B64\u64CD\u4F5C\u9700\u8981\u91CD\u542F Gateway \u624D\u80FD\u751F\u6548\u3002\u662F\u5426\u540C\u65F6\u5207\u6362\u9ED8\u8BA4\u6A21\u578B\uFF1F'},
  'preset.applied_restart':{en:'Preset applied. Restart gateway for default model change.',zh:'\u9884\u8BBE\u5DF2\u5E94\u7528\u3002\u8BF7\u91CD\u542F Gateway \u4EE5\u4F7F\u9ED8\u8BA4\u6A21\u578B\u751F\u6548\u3002'},
  'common.add':{en:'Add',zh:'\u6DFB\u52A0'},
  'common.save':{en:'Save',zh:'\u4FDD\u5B58'},
  'common.delete':{en:'Delete',zh:'\u5220\u9664'},
  'common.test':{en:'Test',zh:'\u6D4B\u8BD5'},
  'common.enabled':{en:'Enabled',zh:'\u542F\u7528'},
  'common.optional':{en:'(optional)',zh:'\uFF08\u53EF\u9009\uFF09'},
  'common.none':{en:'(none)',zh:'\uFF08\u65E0\uFF09'},
  'common.customized':{en:'customized',zh:'\u5DF2\u81EA\u5B9A\u4E49'},
  'common.reset':{en:'Reset Default',zh:'\u6062\u590D\u9ED8\u8BA4'},
  'common.save_failed':{en:'Save failed: ',zh:'\u4FDD\u5B58\u5931\u8D25\uFF1A'},
  'common.loading':{en:'Loading prompts...',zh:'\u52A0\u8F7D\u63D0\u793A\u8BCD\u4E2D...'},
  'common.prompt_saved':{en:'" saved & applied',zh:'" \u5DF2\u4FDD\u5B58\u5E76\u751F\u6548'},
  'chart.cloud':{en:'Cloud',zh:'\u4E91\u7AEF'},
  'chart.local':{en:'Local',zh:'\u672C\u5730'},
  'chart.redacted':{en:'Redacted',zh:'\u8131\u654F'},
  'status.uptime':{en:'Uptime: ',zh:'\u8FD0\u884C\u65F6\u95F4\uFF1A'},
  'status.activity':{en:'Last activity: ',zh:'\u6700\u8FD1\u6D3B\u52A8\uFF1A'},
  'status.updated':{en:'Updated ',zh:'\u5DF2\u66F4\u65B0 '},
  'status.error':{en:'Error: ',zh:'\u9519\u8BEF\uFF1A'},
};
function t(k){return(T[k]&&T[k][LANG])||k;}

function setLang(lang){
  LANG=lang;
  localStorage.setItem('gc-lang',lang);
  document.querySelectorAll('[data-i18n]').forEach(function(el){
    var k=el.getAttribute('data-i18n');
    if(T[k]) el.textContent=t(k);
  });
  document.querySelectorAll('[data-i18n-html]').forEach(function(el){
    var k=el.getAttribute('data-i18n-html');
    if(T[k]) el.innerHTML=t(k);
  });
  document.querySelectorAll('[data-i18n-ph]').forEach(function(el){
    var k=el.getAttribute('data-i18n-ph');
    if(T[k]) el.placeholder=t(k);
  });
  document.querySelectorAll('[data-i18n-opt]').forEach(function(el){
    var k=el.getAttribute('data-i18n-opt');
    if(T[k]) el.textContent=t(k);
  });
  document.getElementById('lang-toggle').textContent=lang==='en'?'\u4E2D\u6587':'EN';
  document.querySelectorAll('.add-row .btn-outline').forEach(function(el){el.textContent=t('common.add');});
  hourlyChart=null;
  refreshAll();
  renderCustomRouterCards();
  updateAvailableRouters();
  loadPrompts();
}
// \u2500\u2500 Generic tag management \u2500\u2500
var _tags = {
  'kw-s2': [], 'kw-s3': [], 'pat-s2': [], 'pat-s3': [],
  'tool-s2': [], 'tool-s3': [], 'toolpath-s2': [], 'toolpath-s3': [],
  'lp': [],
  'pipe-um': [], 'pipe-tcp': [], 'pipe-tce': []
};

var _checkpoints = { um: [], tcp: [], tce: [] };
var _routers = {};

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function renderTags(key) {
  var c = document.getElementById('cfg-tags-' + key);
  if (!c) return;
  c.innerHTML = _tags[key].map(function(v, i) {
    return '<span class="tag">' + escHtml(v) +
      ' <button data-key="' + key + '" data-idx="' + i + '" onclick="removeTag(this)">&times;</button></span>';
  }).join('');
}

function addTag(key) {
  var input = document.getElementById('cfg-tags-' + key + '-input');
  if (!input) return;
  var val = input.value.trim();
  if (val && _tags[key].indexOf(val) === -1) {
    _tags[key].push(val);
    renderTags(key);
  }
  input.value = '';
  input.focus();
}

function removeTag(el) {
  var key = el.getAttribute('data-key');
  var idx = parseInt(el.getAttribute('data-idx'));
  if (key && _tags[key]) {
    _tags[key].splice(idx, 1);
    renderTags(key);
  }
}

// \u2500\u2500 Checkpoint chips \u2500\u2500
function toggleChip(el) {
  var ck = el.getAttribute('data-ck');
  var det = el.getAttribute('data-det');
  if (!ck || !det || !_checkpoints[ck]) return;
  var arr = _checkpoints[ck];
  var idx = arr.indexOf(det);
  if (idx === -1) { arr.push(det); el.classList.add('active'); }
  else { arr.splice(idx, 1); el.classList.remove('active'); }
}

function syncChips() {
  document.querySelectorAll('.chip[data-ck]').forEach(function(el) {
    var ck = el.getAttribute('data-ck');
    var det = el.getAttribute('data-det');
    if (_checkpoints[ck] && _checkpoints[ck].indexOf(det) !== -1) {
      el.classList.add('active');
    } else {
      el.classList.remove('active');
    }
  });
}

// \u2500\u2500 Router management \u2500\u2500
function renderRouters() {
  var c = document.getElementById('cfg-routers-list');
  if (!c) return;
  var ids = Object.keys(_routers);
  if (!ids.length) {
    c.innerHTML = '<div style="color:var(--text-tertiary);font-size:13px;padding:8px 0">No routers configured</div>';
    return;
  }
  c.innerHTML = ids.map(function(id) {
    var r = _routers[id];
    var checked = r.enabled !== false ? ' checked' : '';
    return '<div class="router-card"><div class="rc-head">' +
      '<label class="toggle"><input type="checkbox"' + checked +
      ' data-rid="' + escHtml(id) + '" onchange="toggleRouter(this)"><span class="slider"></span></label>' +
      '<span class="rc-name">' + escHtml(id) + '</span>' +
      '<span class="rc-type">[' + escHtml(r.type || 'builtin') + ']</span>' +
      '<button class="rc-del" data-rid="' + escHtml(id) + '" onclick="removeRouter(this)">&times;</button>' +
      '</div>' +
      (r.module ? '<div class="rc-module">Module: ' + escHtml(r.module) + '</div>' : '') +
      '</div>';
  }).join('');
}

function toggleRouter(el) {
  var id = el.getAttribute('data-rid');
  if (id && _routers[id]) _routers[id].enabled = el.checked;
}

function removeRouter(el) {
  var id = el.getAttribute('data-rid');
  if (id) { delete _routers[id]; renderRouters(); }
}

function addRouter() {
  var idInput = document.getElementById('cfg-router-id-input');
  var typeInput = document.getElementById('cfg-router-type-input');
  var moduleInput = document.getElementById('cfg-router-module-input');
  var id = idInput.value.trim();
  if (!id) return;
  _routers[id] = {
    enabled: true,
    type: typeInput.value || 'builtin',
    module: typeInput.value === 'custom' ? (moduleInput.value.trim() || undefined) : undefined
  };
  renderRouters();
  idInput.value = '';
  moduleInput.value = '';
}

// \u2500\u2500 Model Pricing \u2500\u2500
var _pricing = {};

var DEFAULT_PRICING = {
  'claude-sonnet-4.6': { inputPer1M: 3, outputPer1M: 15 },
  'claude-3.5-sonnet': { inputPer1M: 3, outputPer1M: 15 },
  'claude-3.5-haiku': { inputPer1M: 0.8, outputPer1M: 4 },
  'gpt-4o': { inputPer1M: 2.5, outputPer1M: 10 },
  'gpt-4o-mini': { inputPer1M: 0.15, outputPer1M: 0.6 },
  'o4-mini': { inputPer1M: 1.1, outputPer1M: 4.4 },
  'gemini-2.0-flash': { inputPer1M: 0.1, outputPer1M: 0.4 },
  'deepseek-chat': { inputPer1M: 0.27, outputPer1M: 1.1 }
};

function renderPricing() {
  var tbody = document.getElementById('pricing-body');
  if (!tbody) return;
  var keys = Object.keys(_pricing);
  if (!keys.length) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-tertiary);font-size:13px;padding:14px 0">No pricing configured</td></tr>';
    return;
  }
  tbody.innerHTML = keys.sort().map(function(model) {
    var p = _pricing[model];
    var eid = escHtml(model);
    return '<tr>' +
      '<td style="font-family:var(--font-mono);font-size:12px">' + eid + '</td>' +
      '<td><input type="number" step="0.01" min="0" value="' + (p.inputPer1M ?? 0) + '" data-pricing-model="' + eid + '" data-pricing-field="inputPer1M" onchange="updatePricing(this)" style="width:80px;padding:6px 8px;background:var(--bg-input);border:1px solid transparent;border-radius:4px;font-size:12px;color:var(--text-primary);outline:none"></td>' +
      '<td><input type="number" step="0.01" min="0" value="' + (p.outputPer1M ?? 0) + '" data-pricing-model="' + eid + '" data-pricing-field="outputPer1M" onchange="updatePricing(this)" style="width:80px;padding:6px 8px;background:var(--bg-input);border:1px solid transparent;border-radius:4px;font-size:12px;color:var(--text-primary);outline:none"></td>' +
      '<td><button style="background:none;border:none;color:var(--text-tertiary);cursor:pointer;font-size:14px" onclick="removePricing(\\'' + eid + '\\')">&times;</button></td>' +
      '</tr>';
  }).join('');
}

function updatePricing(el) {
  var model = el.getAttribute('data-pricing-model');
  var field = el.getAttribute('data-pricing-field');
  if (!model || !field || !_pricing[model]) return;
  _pricing[model][field] = parseFloat(el.value) || 0;
}

function addPricingRow() {
  var modelEl = document.getElementById('pricing-new-model');
  var inputEl = document.getElementById('pricing-new-input');
  var outputEl = document.getElementById('pricing-new-output');
  var model = modelEl.value.trim();
  if (!model) return;
  _pricing[model] = {
    inputPer1M: parseFloat(inputEl.value) || 0,
    outputPer1M: parseFloat(outputEl.value) || 0
  };
  modelEl.value = '';
  inputEl.value = '';
  outputEl.value = '';
  modelEl.focus();
  renderPricing();
}

function removePricing(model) {
  delete _pricing[model];
  renderPricing();
}

function loadDefaultPricing() {
  Object.keys(DEFAULT_PRICING).forEach(function(k) {
    if (!_pricing[k]) _pricing[k] = Object.assign({}, DEFAULT_PRICING[k]);
  });
  renderPricing();
}

// \u2500\u2500 Tabs \u2500\u2500
document.querySelectorAll('.tab').forEach(function(t) {
  t.addEventListener('click', function() {
    document.querySelectorAll('.tab').forEach(function(x) { x.classList.remove('active'); });
    document.querySelectorAll('.panel').forEach(function(x) { x.classList.remove('active'); });
    t.classList.add('active');
    document.getElementById(t.dataset.tab + '-panel').classList.add('active');
  });
});

// \u2500\u2500 Formatters \u2500\u2500
function fmt(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}

function timeAgo(ts) {
  var diff = Date.now() - ts;
  if (diff < 60000) return Math.floor(diff / 1000) + 's ago';
  if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
  return Math.floor(diff / 86400000) + 'd ago';
}

function fmtTime(ts) {
  var d = new Date(ts);
  var hh = String(d.getHours()).padStart(2, '0');
  var mm = String(d.getMinutes()).padStart(2, '0');
  var ss = String(d.getSeconds()).padStart(2, '0');
  return hh + ':' + mm + ':' + ss;
}

function fmtCost(n) {
  if (n == null || n === 0) return '$0.00';
  if (n < 0.01) return '<$0.01';
  return '$' + n.toFixed(2);
}

function fillRow(cat, b) {
  var cost = b.estimatedCost || 0;
  return '<tr><td>' + cat + '</td><td>' + fmt(b.inputTokens) + '</td><td>' + fmt(b.outputTokens) +
    '</td><td>' + fmt(b.cacheReadTokens) + '</td><td>' + fmt(b.totalTokens) + '</td><td>' + b.requestCount + '</td><td>' + fmtCost(cost) + '</td></tr>';
}

// \u2500\u2500 Overview \u2500\u2500
async function refreshStats() {
  try {
    var results = await Promise.all([
      fetch(BASE + '/summary').then(function(r) { return r.json(); }),
      fetch(BASE + '/hourly').then(function(r) { return r.json(); }),
    ]);
    var summary = results[0];
    var hourly = results[1];
    if (summary.error) throw new Error(summary.error);

    var lt = summary.lifetime;
    document.getElementById('cloud-tokens').textContent = fmt(lt.cloud.totalTokens);
    document.getElementById('cloud-reqs').textContent = lt.cloud.requestCount + ' ' + t('overview.requests');
    document.getElementById('local-tokens').textContent = fmt(lt.local.totalTokens);
    document.getElementById('local-reqs').textContent = lt.local.requestCount + ' ' + t('overview.requests');
    document.getElementById('proxy-tokens').textContent = fmt(lt.proxy.totalTokens);
    document.getElementById('proxy-reqs').textContent = lt.proxy.requestCount + ' ' + t('overview.requests');

    var total = lt.cloud.totalTokens + lt.local.totalTokens + lt.proxy.totalTokens;
    var prot = lt.local.totalTokens + lt.proxy.totalTokens;
    var rate = total > 0 ? (prot / total * 100).toFixed(1) + '%' : '--';
    document.getElementById('privacy-rate').textContent = rate;
    document.getElementById('privacy-sub').textContent = total > 0
      ? fmt(prot) + ' / ' + fmt(total) + ' ' + t('overview.sub')
      : t('overview.no_data');

    var cloudCost = (lt.cloud.estimatedCost || 0) + (lt.proxy.estimatedCost || 0);
    document.getElementById('cloud-cost').textContent = fmtCost(cloudCost);
    document.getElementById('cloud-cost-sub').textContent = t('overview.cost_sub');

    document.getElementById('detail-body').innerHTML =
      fillRow(t('chart.cloud'), lt.cloud) + fillRow(t('chart.local'), lt.local) + fillRow(t('chart.redacted'), lt.proxy);

    var bs = summary.bySource || {};
    var routerB = bs.router || {inputTokens:0,outputTokens:0,cacheReadTokens:0,totalTokens:0,requestCount:0};
    var taskB = bs.task || {inputTokens:0,outputTokens:0,cacheReadTokens:0,totalTokens:0,requestCount:0};
    document.getElementById('source-body').innerHTML =
      fillRow('\u{1F500} Router (overhead)', routerB) + fillRow('\u26A1 Task (execution)', taskB);

    var infoHtml = '';
    if (summary.startedAt) infoHtml += t('status.uptime') + timeAgo(summary.startedAt);
    if (summary.lastUpdatedAt) infoHtml += ' &middot; ' + t('status.activity') + timeAgo(summary.lastUpdatedAt);
    document.getElementById('info-bar').innerHTML = infoHtml;

    document.getElementById('status-dot').className = 'status-dot';
    document.getElementById('status-text').textContent = t('header.online');
    document.getElementById('last-updated').textContent = t('status.updated') + fmtTime(Date.now());

    updateChart(hourly);
  } catch (e) {
    document.getElementById('status-dot').className = 'status-dot err';
    document.getElementById('status-text').textContent = t('status.error') + (e.message || 'unavailable');
  }
}

async function resetStats() {
  if (!confirm(t('overview.reset_confirm'))) return;
  try {
    var r = await fetch(BASE + '/reset', { method: 'POST' });
    var body = await r.json();
    if (body.error) throw new Error(body.error);
    showToast(t('overview.reset_ok'));
    refreshStats();
    refreshSessions();
  } catch (e) {
    showToast(t('overview.reset_fail') + (e.message || ''), true);
  }
}

function updateChart(hourly) {
  var labels = hourly.map(function(h) { return h.hour.slice(5).replace('T', ' ') + ':00'; });
  var cloudData = hourly.map(function(h) { return h.cloud.totalTokens; });
  var localData = hourly.map(function(h) { return h.local.totalTokens; });
  var proxyData = hourly.map(function(h) { return h.proxy.totalTokens; });
  if (hourlyChart) {
    hourlyChart.data.labels = labels;
    hourlyChart.data.datasets[0].data = cloudData;
    hourlyChart.data.datasets[1].data = localData;
    hourlyChart.data.datasets[2].data = proxyData;
    hourlyChart.update('none');
  } else {
    var ctx = document.getElementById('hourlyChart');
    if (!ctx) return;
    hourlyChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [
          { label: t('chart.cloud'), data: cloudData, borderColor: '#2563eb', backgroundColor: 'rgba(37,99,235,0.06)', fill: true, tension: 0.4, borderWidth: 2 },
          { label: t('chart.local'), data: localData, borderColor: '#059669', backgroundColor: 'rgba(5,150,105,0.06)', fill: true, tension: 0.4, borderWidth: 2 },
          { label: t('chart.redacted'), data: proxyData, borderColor: '#d97706', backgroundColor: 'rgba(217,119,6,0.06)', fill: true, tension: 0.4, borderWidth: 2 },
        ],
      },
      options: {
        responsive: true,
        plugins: { legend: { labels: { color: '#6e6e80', usePointStyle: true, pointStyle: 'circle', padding: 20, font: { size: 12, weight: 500 } } } },
        scales: {
          x: { ticks: { color: '#9ca3af', maxTicksLimit: 12, font: { size: 11 } }, grid: { color: 'rgba(0,0,0,.04)' } },
          y: { ticks: { color: '#9ca3af', font: { size: 11 } }, grid: { color: 'rgba(0,0,0,.04)' } },
        },
      },
    });
  }
}

// \u2500\u2500 Sessions \u2500\u2500
function totalForSession(s) {
  return s.cloud.totalTokens + s.local.totalTokens + s.proxy.totalTokens;
}
function totalReqsForSession(s) {
  return s.cloud.requestCount + s.local.requestCount + s.proxy.requestCount;
}

async function refreshSessions() {
  try {
    var sessions = await fetch(BASE + '/sessions').then(function(r) { return r.json(); });
    var tbody = document.getElementById('sessions-body');
    if (!sessions || !sessions.length) {
      tbody.innerHTML = '<tr><td colspan="11" class="empty-state">' + t('sessions.empty') + '</td></tr>';
      return;
    }
    tbody.innerHTML = sessions.map(function(s) {
      var shortKey = s.sessionKey.length > 20 ? s.sessionKey.slice(0, 20) + '...' : s.sessionKey;
      var bs = s.bySource || {};
      var routerTokens = (bs.router || {}).totalTokens || 0;
      var taskTokens = (bs.task || {}).totalTokens || 0;
      var sessCost = (s.cloud.estimatedCost || 0) + (s.proxy.estimatedCost || 0);
      return '<tr>' +
        '<td><span class="session-key" title="' + escHtml(s.sessionKey) + '">' + escHtml(shortKey) + '</span></td>' +
        '<td><span class="level-tag level-' + s.highestLevel + '">' + s.highestLevel + '</span></td>' +
        '<td>' + fmt(s.cloud.totalTokens) + '</td>' +
        '<td>' + fmt(s.local.totalTokens) + '</td>' +
        '<td>' + fmt(s.proxy.totalTokens) + '</td>' +
        '<td>' + fmt(routerTokens) + '</td>' +
        '<td>' + fmt(taskTokens) + '</td>' +
        '<td>' + fmt(totalForSession(s)) + '</td>' +
        '<td>' + fmtCost(sessCost) + '</td>' +
        '<td>' + totalReqsForSession(s) + '</td>' +
        '<td>' + timeAgo(s.lastActiveAt) + '</td>' +
        '</tr>';
    }).join('');
  } catch (e) { /* non-critical */ }
}

// \u2500\u2500 Detection Log \u2500\u2500
async function refreshDetections() {
  try {
    _detections = await fetch(BASE + '/detections').then(function(r) { return r.json(); });
    renderDetections();
  } catch (e) { /* non-critical */ }
}

function filterDetections(level, el) {
  _detectionFilter = level;
  document.querySelectorAll('.filter-btn').forEach(function(b) { b.classList.remove('active'); });
  if (el) el.classList.add('active');
  renderDetections();
}

function renderDetections() {
  var tbody = document.getElementById('detections-body');
  var filtered = _detectionFilter === 'all'
    ? _detections
    : _detections.filter(function(d) { return d.level === _detectionFilter; });
  if (!filtered || !filtered.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">' +
      (_detectionFilter !== 'all' ? t('det.empty_for') + _detectionFilter : t('det.empty')) + '</td></tr>';
    return;
  }
  tbody.innerHTML = filtered.slice(0, 100).map(function(d) {
    var shortKey = d.sessionKey.length > 16 ? d.sessionKey.slice(0, 16) + '...' : d.sessionKey;
    return '<tr>' +
      '<td>' + fmtTime(d.timestamp) + '</td>' +
      '<td><span class="session-key" title="' + escHtml(d.sessionKey) + '">' + escHtml(shortKey) + '</span></td>' +
      '<td><span class="level-tag level-' + d.level + '">' + d.level + '</span></td>' +
      '<td><span class="checkpoint-tag">' + escHtml(d.checkpoint || '--') + '</span></td>' +
      '<td>' + escHtml(d.reason || '--') + '</td>' +
      '</tr>';
  }).join('');
}

// \u2500\u2500 Config \u2500\u2500
function toggleModuleField() {
  var wrap = document.getElementById('cfg-lm-module-wrap');
  wrap.style.display = document.getElementById('cfg-lm-type').value === 'custom' ? 'block' : 'none';
}

async function loadConfig() {
  try {
    var cfg = await fetch(BASE + '/config').then(function(r) { return r.json(); });
    var p = cfg.privacy || {};
    var lm = p.localModel || {};
    var ga = p.guardAgent || {};
    var rules = p.rules || {};
    var sess = p.session || {};
    var ck = p.checkpoints || {};
    var routers = p.routers || {};
    var pipeline = p.pipeline || {};

    document.getElementById('cfg-enabled').checked = p.enabled !== false;
    document.getElementById('cfg-lm-enabled').checked = lm.enabled !== false;
    document.getElementById('cfg-lm-type').value = lm.type || 'openai-compatible';
    document.getElementById('cfg-lm-provider').value = lm.provider || '';
    document.getElementById('cfg-lm-endpoint').value = lm.endpoint || '';
    document.getElementById('cfg-lm-model').value = lm.model || '';
    document.getElementById('cfg-lm-apikey').value = lm.apiKey || '';
    document.getElementById('cfg-lm-module').value = lm.module || '';

    document.getElementById('cfg-ga-id').value = ga.id || '';
    document.getElementById('cfg-ga-workspace').value = ga.workspace || '';
    document.getElementById('cfg-ga-model').value = ga.model || '';

    document.getElementById('cfg-s2policy').value = p.s2Policy || 'proxy';
    document.getElementById('cfg-proxyport').value = p.proxyPort || '';

    document.getElementById('cfg-sess-isolate').checked = sess.isolateGuardHistory !== false;
    document.getElementById('cfg-sess-basedir').value = sess.baseDir || '';

    var rd = p.redaction || {};
    ['internalIp','email','envVar','creditCard','chinesePhone','chineseId','chineseAddress','pin'].forEach(function(k) {
      var el = document.getElementById('cfg-rd-' + k);
      if (el) el.checked = !!rd[k];
    });

    _checkpoints.um = Array.isArray(ck.onUserMessage) ? ck.onUserMessage.slice() : [];
    _checkpoints.tcp = Array.isArray(ck.onToolCallProposed) ? ck.onToolCallProposed.slice() : [];
    _checkpoints.tce = Array.isArray(ck.onToolCallExecuted) ? ck.onToolCallExecuted.slice() : [];
    syncChips();

    _tags['kw-s2'] = (rules.keywords && rules.keywords.S2) ? rules.keywords.S2.slice() : [];
    _tags['kw-s3'] = (rules.keywords && rules.keywords.S3) ? rules.keywords.S3.slice() : [];
    _tags['pat-s2'] = (rules.patterns && rules.patterns.S2) ? rules.patterns.S2.slice() : [];
    _tags['pat-s3'] = (rules.patterns && rules.patterns.S3) ? rules.patterns.S3.slice() : [];
    var toolRules = rules.tools || {};
    _tags['tool-s2'] = (toolRules.S2 && toolRules.S2.tools) ? toolRules.S2.tools.slice() : [];
    _tags['tool-s3'] = (toolRules.S3 && toolRules.S3.tools) ? toolRules.S3.tools.slice() : [];
    _tags['toolpath-s2'] = (toolRules.S2 && toolRules.S2.paths) ? toolRules.S2.paths.slice() : [];
    _tags['toolpath-s3'] = (toolRules.S3 && toolRules.S3.paths) ? toolRules.S3.paths.slice() : [];
    _tags['lp'] = Array.isArray(p.localProviders) ? p.localProviders.slice() : [];

    _pricing = {};
    if (p.modelPricing && typeof p.modelPricing === 'object') {
      Object.keys(p.modelPricing).forEach(function(k) {
        _pricing[k] = Object.assign({}, p.modelPricing[k]);
      });
    }
    renderPricing();

    _tags['pipe-um'] = Array.isArray(pipeline.onUserMessage) ? pipeline.onUserMessage.slice() : [];
    _tags['pipe-tcp'] = Array.isArray(pipeline.onToolCallProposed) ? pipeline.onToolCallProposed.slice() : [];
    _tags['pipe-tce'] = Array.isArray(pipeline.onToolCallExecuted) ? pipeline.onToolCallExecuted.slice() : [];

    _routers = {};
    if (routers && typeof routers === 'object') {
      Object.keys(routers).forEach(function(k) { _routers[k] = Object.assign({}, routers[k]); });
    }

    // Privacy router enable toggle
    var privacyReg = _routers['privacy'] || {};
    var privacyEl = document.getElementById('cfg-privacy-enabled');
    if (privacyEl) privacyEl.checked = privacyReg.enabled !== false;

    Object.keys(_tags).forEach(function(k) {
      if (k.indexOf('pipe-') === 0) return;
      renderTags(k);
    });
    toggleModuleField();
    loadTokenSaverConfig();
    renderCustomRouterCards();
    updateAvailableRouters();
  } catch (e) { /* non-critical, fields stay at defaults */ }
}

document.getElementById('cfg-lm-type').addEventListener('change', toggleModuleField);

// \u2500\u2500 Presets \u2500\u2500

var _presets = [];
var _activePreset = null;
var _currentDefaultModel = null;

async function loadPresets() {
  try {
    var data = await fetch(BASE + '/presets').then(function(r) { return r.json(); });
    _presets = data.presets || [];
    _activePreset = data.activePreset || null;
    _currentDefaultModel = data.currentDefaultModel || null;
    renderPresetSelect();
  } catch (e) { /* non-critical */ }
}

function renderPresetSelect() {
  var sel = document.getElementById('preset-select');
  var builtins = _presets.filter(function(p) { return p.builtin; });
  var customs = _presets.filter(function(p) { return !p.builtin; });
  var html = '<option value="">' + t('preset.select_ph') + '</option>';
  if (builtins.length) {
    html += '<optgroup label="' + t('preset.builtin') + '">';
    builtins.forEach(function(p) {
      var dm = p.defaultModel ? ' [' + p.defaultModel + ']' : '';
      html += '<option value="' + p.id + '"' + (p.id === _activePreset ? ' selected' : '') + '>' + escHtml(p.name) + escHtml(dm) + '</option>';
    });
    html += '</optgroup>';
  }
  if (customs.length) {
    html += '<optgroup label="' + t('preset.custom') + '">';
    customs.forEach(function(p) {
      var dm = p.defaultModel ? ' [' + p.defaultModel + ']' : '';
      html += '<option value="' + p.id + '"' + (p.id === _activePreset ? ' selected' : '') + '>' + escHtml(p.name) + escHtml(dm) + '</option>';
    });
    html += '</optgroup>';
  }
  sel.innerHTML = html;
  onPresetSelectChange();
}

function onPresetSelectChange() {
  var id = document.getElementById('preset-select').value;
  var preset = _presets.find(function(p) { return p.id === id; });
  var deleteBtn = document.getElementById('preset-delete-btn');
  deleteBtn.style.display = (preset && !preset.builtin) ? 'inline-block' : 'none';
  var infoEl = document.getElementById('preset-info');
  if (preset && preset.defaultModel) {
    infoEl.textContent = t('preset.includes_default') + preset.defaultModel;
    infoEl.style.display = 'block';
  } else {
    infoEl.style.display = 'none';
  }
}

async function applyPreset() {
  var id = document.getElementById('preset-select').value;
  if (!id) { showToast(t('preset.select_first'), true); return; }
  var preset = _presets.find(function(p) { return p.id === id; });
  var applyDefaultModel = false;

  if (preset && preset.defaultModel && preset.defaultModel !== _currentDefaultModel) {
    applyDefaultModel = confirm(
      t('preset.confirm_default_1') + preset.defaultModel +
      t('preset.confirm_default_2')
    );
  }

  try {
    var res = await fetch(BASE + '/presets/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: id, applyDefaultModel: applyDefaultModel }),
    });
    var result = await res.json();
    if (result.ok) {
      _activePreset = id;
      if (result.needsRestart) {
        showToast(t('preset.applied_restart'));
      } else if (result.defaultModelError) {
        showToast(t('preset.applied') + ' (' + result.defaultModelError + ')', true);
      } else {
        showToast(t('preset.applied'));
      }
      loadConfig();
      loadPresets();
    } else {
      showToast(t('common.save_failed') + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast(t('common.save_failed') + e.message, true);
  }
}

async function saveAsPreset() {
  var name = document.getElementById('preset-save-name').value.trim();
  if (!name) { showToast(t('preset.name_required'), true); return; }
  try {
    var res = await fetch(BASE + '/presets/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name }),
    });
    var result = await res.json();
    if (result.ok) {
      document.getElementById('preset-save-name').value = '';
      showToast(t('preset.saved'));
      loadPresets();
    } else {
      showToast(t('common.save_failed') + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast(t('common.save_failed') + e.message, true);
  }
}

async function deletePreset() {
  var id = document.getElementById('preset-select').value;
  if (!id) return;
  if (!confirm(t('preset.delete_confirm'))) return;
  try {
    var res = await fetch(BASE + '/presets/' + encodeURIComponent(id), {
      method: 'DELETE',
    });
    var result = await res.json();
    if (result.ok) {
      showToast(t('preset.deleted'));
      loadPresets();
    } else {
      showToast(t('common.save_failed') + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast(t('common.save_failed') + e.message, true);
  }
}

async function saveConfig() {
  try {
    var typeVal = document.getElementById('cfg-lm-type').value;
    var portVal = document.getElementById('cfg-proxyport').value;

    var payload = {
      privacy: {
        enabled: document.getElementById('cfg-enabled').checked,
        localModel: {
          enabled: document.getElementById('cfg-lm-enabled').checked,
          type: typeVal || undefined,
          provider: document.getElementById('cfg-lm-provider').value || undefined,
          endpoint: document.getElementById('cfg-lm-endpoint').value || undefined,
          model: document.getElementById('cfg-lm-model').value || undefined,
          apiKey: document.getElementById('cfg-lm-apikey').value || undefined,
          module: typeVal === 'custom' ? (document.getElementById('cfg-lm-module').value || undefined) : undefined,
        },
        guardAgent: {
          id: document.getElementById('cfg-ga-id').value || undefined,
          workspace: document.getElementById('cfg-ga-workspace').value || undefined,
          model: document.getElementById('cfg-ga-model').value || undefined,
        },
        s2Policy: document.getElementById('cfg-s2policy').value,
        proxyPort: portVal ? parseInt(portVal) : undefined,
        localProviders: _tags['lp'].length > 0 ? _tags['lp'] : [],
        modelPricing: Object.keys(_pricing).length > 0 ? _pricing : undefined,
        session: {
          isolateGuardHistory: document.getElementById('cfg-sess-isolate').checked,
          baseDir: document.getElementById('cfg-sess-basedir').value || undefined,
        },
        redaction: (function() {
          var rd = {};
          ['internalIp','email','envVar','creditCard','chinesePhone','chineseId','chineseAddress','pin'].forEach(function(k) {
            var el = document.getElementById('cfg-rd-' + k);
            if (el) rd[k] = el.checked;
          });
          return rd;
        })(),
      },
    };
    var res = await fetch(BASE + '/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    var result = await res.json();
    if (result.ok) {
      showToast(t('cfg.saved'));
      loadPresets();
    } else {
      showToast(t('common.save_failed') + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast(t('common.save_failed') + e.message, true);
  }
}

function showToast(msg, isError) {
  var el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast' + (isError ? ' error' : '');
  el.style.display = 'block';
  setTimeout(function() { el.style.display = 'none'; }, 3000);
}

function refreshAll() {
  refreshStats();
  refreshSessions();
  refreshDetections();
}

// \u2500\u2500 Prompt Editors \u2500\u2500

var _prompts = {};

async function loadPrompts() {
  try {
    _prompts = await fetch(BASE + '/prompts').then(function(r) { return r.json(); });
    renderRouterPrompts('privacy-prompt-main', PRIVACY_PROMPTS_MAIN);
    renderRouterPrompts('privacy-prompt-adv', PRIVACY_PROMPTS_ADV);
    renderRouterPrompts('tokensaver-prompt-editors', TOKENSAVER_PROMPTS);
  } catch (e) { /* non-critical */ }
}

async function savePrompt(name) {
  var el = document.getElementById('prompt-' + name);
  if (!el) return;
  try {
    var res = await fetch(BASE + '/prompts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name, content: el.value }),
    });
    var result = await res.json();
    if (result.ok) {
      showToast('"' + name + t('common.prompt_saved'));
      loadPrompts();
    } else {
      showToast(t('common.save_failed') + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast(t('common.save_failed') + e.message, true);
  }
}

function resetPrompt(name) {
  if (!_prompts[name]) return;
  var el = document.getElementById('prompt-' + name);
  if (el) el.value = _prompts[name].defaultContent;
}

// \u2500\u2500 Test Classify \u2500\u2500

async function runTestClassify() {
  var msg = document.getElementById('test-message').value.trim();
  if (!msg) { showToast(t('test.enter_msg'), true); return; }
  var checkpoint = document.getElementById('test-checkpoint').value;
  var resultEl = document.getElementById('test-result');
  var loadingEl = document.getElementById('test-loading');
  resultEl.classList.remove('visible');
  loadingEl.style.display = 'block';
  try {
    var res = await fetch(BASE + '/test-classify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg, checkpoint: checkpoint }),
    });
    var data = await res.json();
    loadingEl.style.display = 'none';
    if (data.error) {
      showToast(t('test.failed') + data.error, true);
      return;
    }
    document.getElementById('tr-level').innerHTML = '<span class="level-tag level-' + data.level + '">' + data.level + '</span>';
    document.getElementById('tr-action').textContent = data.action || 'passthrough';
    document.getElementById('tr-target').textContent = data.target ? (data.target.provider + '/' + data.target.model) : t('common.none');
    document.getElementById('tr-router').textContent = data.routerId || t('common.none');
    document.getElementById('tr-reason').textContent = data.reason || t('common.none');
    document.getElementById('tr-confidence').textContent = data.confidence != null ? (data.confidence * 100).toFixed(0) + '%' : '-';
    var perEl = document.getElementById('tr-per-router');
    if (data.routers && data.routers.length > 0) {
      var html = '<div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border-subtle)">' +
        '<div style="font-size:11px;text-transform:uppercase;color:var(--text-tertiary);letter-spacing:.06em;font-weight:700;margin-bottom:10px">' + t('test.individual') + '</div>';
      data.routers.forEach(function(r) {
        html += '<div style="background:var(--bg-surface);border:1px solid var(--border-subtle);border-radius:8px;padding:12px 16px;margin-bottom:6px">' +
          '<div style="display:flex;justify-content:space-between;align-items:center">' +
          '<span style="font-weight:600;color:var(--text-primary);font-size:13px">' + (r.routerId || '?') + '</span>' +
          '<span class="level-tag level-' + r.level + '">' + r.level + '</span></div>' +
          '<div style="font-size:12px;color:var(--text-secondary);margin-top:4px">' +
          (r.action || 'passthrough') +
          (r.target ? ' \u2192 ' + r.target.provider + '/' + r.target.model : '') +
          '</div>' +
          '<div style="font-size:12px;color:var(--text-tertiary);margin-top:2px">' + (r.reason || '-') + '</div>' +
          '</div>';
      });
      html += '</div>';
      perEl.innerHTML = html;
    } else {
      perEl.innerHTML = '';
    }
    resultEl.classList.add('visible');
  } catch (e) {
    loadingEl.style.display = 'none';
    showToast(t('test.failed') + e.message, true);
  }
}

// \u2500\u2500 Section Collapse \u2500\u2500

function toggleSection(el) {
  el.classList.toggle('collapsed');
  var body = el.nextElementSibling;
  if (body) body.classList.toggle('collapsed');
}

function toggleAdv(el) {
  el.classList.toggle('open');
  var body = el.nextElementSibling;
  if (body) body.classList.toggle('open');
}

// \u2500\u2500 Per-Router Prompt Rendering \u2500\u2500

var PRIVACY_PROMPTS_MAIN = ['detection-system'];
var PRIVACY_PROMPTS_ADV = ['pii-extraction'];
var TOKENSAVER_PROMPTS = ['token-saver-judge'];

function renderRouterPrompts(containerId, promptNames) {
  var c = document.getElementById(containerId);
  if (!c) return;
  var html = '';
  promptNames.forEach(function(name) {
    var p = _prompts[name];
    if (!p) return;
    var customBadge = p.isCustom ? '<span class="custom-badge">' + t('common.customized') + '</span>' : '';
    html += '<div style="margin-bottom:16px">' +
      '<div class="prompt-header">' +
        '<h4>' + escHtml(p.label) + customBadge + '</h4>' +
        '<div class="prompt-actions">' +
          '<button class="btn btn-sm btn-outline" onclick="resetPrompt(\\'' + escHtml(name) + '\\')">' + t('common.reset') + '</button>' +
          '<button class="btn btn-sm btn-primary" onclick="savePrompt(\\'' + escHtml(name) + '\\')">' + t('common.save') + '</button>' +
        '</div>' +
      '</div>' +
      '<textarea class="prompt-editor" id="prompt-' + escHtml(name) + '">' + escHtml(p.content) + '</textarea>' +
    '</div>';
  });
  c.innerHTML = html || '<div style="color:var(--text-tertiary);font-size:13px">' + t('common.loading') + '</div>';
}

// \u2500\u2500 Per-Router Test \u2500\u2500

async function runRouterTest(routerId) {
  var msgEl = document.getElementById('test-' + routerId + '-message');
  var msg = msgEl ? msgEl.value.trim() : '';
  if (!msg) { showToast(t('test.enter_msg'), true); return; }
  var resultEl = document.getElementById('test-' + routerId + '-result');
  var loadingEl = document.getElementById('test-' + routerId + '-loading');
  resultEl.classList.remove('visible');
  loadingEl.style.display = 'block';
  try {
    var res = await fetch(BASE + '/test-classify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg, router: routerId }),
    });
    var data = await res.json();
    loadingEl.style.display = 'none';
    if (data.error) {
      showToast(t('test.failed') + data.error, true);
      return;
    }
    document.getElementById('tr-' + routerId + '-level').innerHTML = '<span class="level-tag level-' + data.level + '">' + data.level + '</span>';
    document.getElementById('tr-' + routerId + '-action').textContent = data.action || 'passthrough';
    document.getElementById('tr-' + routerId + '-target').textContent = data.target ? (data.target.provider + '/' + data.target.model) : t('common.none');
    document.getElementById('tr-' + routerId + '-reason').textContent = data.reason || t('common.none');
    document.getElementById('tr-' + routerId + '-confidence').textContent = data.confidence != null ? (data.confidence * 100).toFixed(0) + '%' : '-';
    resultEl.classList.add('visible');
  } catch (e) {
    loadingEl.style.display = 'none';
    showToast(t('test.failed') + e.message, true);
  }
}

// \u2500\u2500 Save Privacy Router \u2500\u2500

async function savePrivacyRouter() {
  try {
    var payload = {
      privacy: {
        checkpoints: {
          onUserMessage: _checkpoints.um.length ? _checkpoints.um : undefined,
          onToolCallProposed: _checkpoints.tcp.length ? _checkpoints.tcp : undefined,
          onToolCallExecuted: _checkpoints.tce.length ? _checkpoints.tce : undefined,
        },
        rules: {
          keywords: { S2: _tags['kw-s2'], S3: _tags['kw-s3'] },
          patterns: { S2: _tags['pat-s2'], S3: _tags['pat-s3'] },
          tools: {
            S2: { tools: _tags['tool-s2'], paths: _tags['toolpath-s2'] },
            S3: { tools: _tags['tool-s3'], paths: _tags['toolpath-s3'] },
          },
        },
      },
    };
    var res = await fetch(BASE + '/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    var result = await res.json();
    if (result.ok) {
      showToast(t('priv.saved'));
    } else {
      showToast(t('common.save_failed') + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast(t('common.save_failed') + e.message, true);
  }
}

// \u2500\u2500 Save Token-Saver Config \u2500\u2500

async function saveTokenSaverConfig() {
  try {
    var tiers = {};
    ['SIMPLE','MEDIUM','COMPLEX','REASONING'].forEach(function(t) {
      var p = document.getElementById('cfg-ts-tier-' + t + '-provider');
      var m = document.getElementById('cfg-ts-tier-' + t + '-model');
      if (p && m && (p.value || m.value)) {
        tiers[t] = { provider: p.value, model: m.value };
      }
    });
    var cacheTtlEl = document.getElementById('cfg-ts-cachettl');
    var cacheTtl = cacheTtlEl && cacheTtlEl.value ? parseInt(cacheTtlEl.value) : undefined;
    var enabled = document.getElementById('cfg-ts-enabled').checked;

    var payload = {
      privacy: {
        routers: {
          'token-saver': {
            enabled: enabled,
            type: 'builtin',
            options: {
              tiers: Object.keys(tiers).length > 0 ? tiers : undefined,
              cacheTtlMs: cacheTtl,
            },
          },
        },
      },
    };

    // Also add token-saver to pipeline.onUserMessage if enabling
    if (enabled) {
      var currentPipe = _tags['pipe-um'] || [];
      if (currentPipe.indexOf('token-saver') === -1) {
        payload.privacy.pipeline = {
          onUserMessage: currentPipe.concat(['token-saver']),
        };
      }
    }

    var res = await fetch(BASE + '/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    var result = await res.json();
    if (result.ok) {
      showToast(t('co.saved') || 'Cost-Optimizer saved');
      loadConfig();
    } else {
      showToast(t('common.save_failed') + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast(t('common.save_failed') + e.message, true);
  }
}

// \u2500\u2500 Save Pipeline Order \u2500\u2500

async function savePipelineOrder() {
  try {
    var payload = {
      privacy: {
        pipeline: {
          onUserMessage: _tags['pipe-um'].length ? _tags['pipe-um'] : undefined,
          onToolCallProposed: _tags['pipe-tcp'].length ? _tags['pipe-tcp'] : undefined,
          onToolCallExecuted: _tags['pipe-tce'].length ? _tags['pipe-tce'] : undefined,
        },
      },
    };
    var res = await fetch(BASE + '/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    var result = await res.json();
    if (result.ok) {
      showToast(t('pipe.saved'));
    } else {
      showToast(t('common.save_failed') + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast(t('common.save_failed') + e.message, true);
  }
}

// \u2500\u2500 Custom Routers \u2500\u2500

var BUILTIN_ROUTERS = ['privacy', 'token-saver'];
var _customRouterData = {};

function getCustomRouterIds() {
  return Object.keys(_routers).filter(function(id) {
    return BUILTIN_ROUTERS.indexOf(id) === -1 && _routers[id].type === 'configurable';
  });
}

function renderCustomRouterCards() {
  var container = document.getElementById('custom-router-cards');
  if (!container) return;
  var ids = getCustomRouterIds();
  if (!ids.length) { container.innerHTML = ''; return; }

  container.innerHTML = ids.map(function(id) {
    var r = _routers[id] || {};
    var opts = r.options || {};
    var checked = r.enabled !== false ? ' checked' : '';
    var kwS2 = (opts.keywords && opts.keywords.S2) ? opts.keywords.S2 : [];
    var kwS3 = (opts.keywords && opts.keywords.S3) ? opts.keywords.S3 : [];
    var patS2 = (opts.patterns && opts.patterns.S2) ? opts.patterns.S2 : [];
    var patS3 = (opts.patterns && opts.patterns.S3) ? opts.patterns.S3 : [];
    var prompt = opts.prompt || '';

    // init tag arrays for this custom router
    _tags['cr-kw-s2-' + id] = kwS2.slice();
    _tags['cr-kw-s3-' + id] = kwS3.slice();
    _tags['cr-pat-s2-' + id] = patS2.slice();
    _tags['cr-pat-s3-' + id] = patS3.slice();

    return '<div class="router-section" id="cr-card-' + escHtml(id) + '">' +
      '<div class="router-section-header" onclick="toggleSection(this)">' +
        '<span class="section-arrow">&#9660;</span>' +
        '<h3>' + escHtml(id) + '</h3>' +
        '<span class="router-id-badge">configurable</span>' +
        '<button class="btn btn-sm btn-danger" style="margin-left:auto" onclick="event.stopPropagation();removeCustomRouter(\\'' + escHtml(id) + '\\')">' + t('common.delete') + '</button>' +
      '</div>' +
      '<div class="router-section-body">' +
        '<div class="field-toggle" style="margin-bottom:18px">' +
          '<label>' + t('common.enabled') + '</label>' +
          '<label class="toggle"><input type="checkbox" id="cfg-cr-enabled-' + escHtml(id) + '"' + checked + '><span class="slider"></span></label>' +
        '</div>' +

        '<div class="subsection">' +
          '<h4>' + t('cr.kw_rules') + '</h4>' +
          '<div class="rules-grid">' +
            '<div class="rules-col">' +
              '<h4>' + t('cr.s2_kw') + '</h4>' +
              '<div class="tag-list" id="cfg-tags-cr-kw-s2-' + escHtml(id) + '"></div>' +
              '<div class="add-row">' +
                '<input id="cfg-tags-cr-kw-s2-' + escHtml(id) + '-input" placeholder="Add S2 keyword" onkeydown="if(event.key===\\'Enter\\'){event.preventDefault();addTag(\\'cr-kw-s2-' + escHtml(id) + '\\')}"><button class="btn btn-sm btn-outline" onclick="addTag(\\'cr-kw-s2-' + escHtml(id) + '\\')">Add</button>' +
              '</div>' +
              '<div style="margin-top:14px"><h4 style="font-size:11px;color:var(--text-tertiary);margin-bottom:8px;text-transform:uppercase;letter-spacing:.06em;font-weight:700">' + t('cr.s2_pat') + '</h4></div>' +
              '<div class="tag-list" id="cfg-tags-cr-pat-s2-' + escHtml(id) + '"></div>' +
              '<div class="add-row">' +
                '<input id="cfg-tags-cr-pat-s2-' + escHtml(id) + '-input" placeholder="Add S2 pattern" onkeydown="if(event.key===\\'Enter\\'){event.preventDefault();addTag(\\'cr-pat-s2-' + escHtml(id) + '\\')}"><button class="btn btn-sm btn-outline" onclick="addTag(\\'cr-pat-s2-' + escHtml(id) + '\\')">Add</button>' +
              '</div>' +
            '</div>' +
            '<div class="rules-col">' +
              '<h4>' + t('cr.s3_kw') + '</h4>' +
              '<div class="tag-list" id="cfg-tags-cr-kw-s3-' + escHtml(id) + '"></div>' +
              '<div class="add-row">' +
                '<input id="cfg-tags-cr-kw-s3-' + escHtml(id) + '-input" placeholder="Add S3 keyword" onkeydown="if(event.key===\\'Enter\\'){event.preventDefault();addTag(\\'cr-kw-s3-' + escHtml(id) + '\\')}"><button class="btn btn-sm btn-outline" onclick="addTag(\\'cr-kw-s3-' + escHtml(id) + '\\')">Add</button>' +
              '</div>' +
              '<div style="margin-top:14px"><h4 style="font-size:11px;color:var(--text-tertiary);margin-bottom:8px;text-transform:uppercase;letter-spacing:.06em;font-weight:700">' + t('cr.s3_pat') + '</h4></div>' +
              '<div class="tag-list" id="cfg-tags-cr-pat-s3-' + escHtml(id) + '"></div>' +
              '<div class="add-row">' +
                '<input id="cfg-tags-cr-pat-s3-' + escHtml(id) + '-input" placeholder="Add S3 pattern" onkeydown="if(event.key===\\'Enter\\'){event.preventDefault();addTag(\\'cr-pat-s3-' + escHtml(id) + '\\')}"><button class="btn btn-sm btn-outline" onclick="addTag(\\'cr-pat-s3-' + escHtml(id) + '\\')">Add</button>' +
              '</div>' +
            '</div>' +
          '</div>' +
        '</div>' +

        '<div class="subsection">' +
          '<h4>' + t('cr.cls_prompt') + ' <span style="font-size:11px;color:var(--text-tertiary);text-transform:none;letter-spacing:0;font-weight:400">' + t('common.optional') + '</span></h4>' +
          '<div class="hint" style="margin-bottom:10px">' + t('cr.cls_hint') + '</div>' +
          '<textarea class="prompt-editor" id="cr-prompt-' + escHtml(id) + '">' + escHtml(prompt) + '</textarea>' +
        '</div>' +

        '<div class="subsection">' +
          '<h4>' + t('common.test') + ' (' + escHtml(id) + ')</h4>' +
          '<textarea class="test-input" id="test-' + escHtml(id) + '-message" placeholder="' + escHtml(t('test.enter_msg')) + '..."></textarea>' +
          '<div style="display:flex;gap:8px;margin-top:10px;align-items:center">' +
            '<button class="btn btn-primary btn-sm" onclick="runRouterTest(\\'' + escHtml(id) + '\\')">' + t('common.test') + '</button>' +
          '</div>' +
          '<div class="test-result" id="test-' + escHtml(id) + '-result">' +
            '<div class="test-result-row"><span class="test-result-label">' + t('test.level') + '</span><span class="test-result-value" id="tr-' + escHtml(id) + '-level">-</span></div>' +
            '<div class="test-result-row"><span class="test-result-label">' + t('test.action') + '</span><span class="test-result-value" id="tr-' + escHtml(id) + '-action">-</span></div>' +
            '<div class="test-result-row"><span class="test-result-label">' + t('test.target') + '</span><span class="test-result-value" id="tr-' + escHtml(id) + '-target">-</span></div>' +
            '<div class="test-result-row"><span class="test-result-label">' + t('test.reason') + '</span><span class="test-result-value" id="tr-' + escHtml(id) + '-reason">-</span></div>' +
            '<div class="test-result-row"><span class="test-result-label">' + t('test.confidence') + '</span><span class="test-result-value" id="tr-' + escHtml(id) + '-confidence">-</span></div>' +
          '</div>' +
          '<div class="test-loading" id="test-' + escHtml(id) + '-loading" style="display:none">' + t('test.testing') + '</div>' +
        '</div>' +

        '<div class="save-bar"><button class="btn btn-primary" onclick="saveCustomRouter(\\'' + escHtml(id) + '\\')">' + t('common.save') + ' ' + escHtml(id) + '</button></div>' +
      '</div>' +
    '</div>';
  }).join('');

  // render tags for custom routers after DOM is built
  ids.forEach(function(id) {
    renderTags('cr-kw-s2-' + id);
    renderTags('cr-kw-s3-' + id);
    renderTags('cr-pat-s2-' + id);
    renderTags('cr-pat-s3-' + id);
  });
}

function getAllRouterIds() {
  var allIds = Object.keys(_routers);
  if (!allIds.length) allIds = BUILTIN_ROUTERS.slice();
  BUILTIN_ROUTERS.forEach(function(b) {
    if (allIds.indexOf(b) === -1) allIds.unshift(b);
  });
  return allIds;
}

function renderPipePicker(pipeKey) {
  var suffix = pipeKey.replace('pipe-', '');
  var container = document.getElementById('pipe-picker-' + suffix);
  if (!container) return;
  var current = _tags[pipeKey] || [];
  var allIds = getAllRouterIds();
  container.innerHTML = allIds.map(function(id) {
    var inUse = current.indexOf(id) !== -1;
    return '<button class="pipe-pick-btn' + (inUse ? ' in-use' : '') + '" onclick="togglePipeRouter(\\'' + escHtml(pipeKey) + '\\',\\'' + escHtml(id) + '\\')">' +
      '+ ' + escHtml(id) + '</button>';
  }).join('');
}

function renderPipeTags(pipeKey) {
  var c = document.getElementById('cfg-tags-' + pipeKey);
  if (!c) return;
  c.innerHTML = _tags[pipeKey].map(function(v, i) {
    return '<span class="tag pipe-tag" draggable="true" data-pipe="' + pipeKey + '" data-idx="' + i + '">' +
      '<span style="color:var(--text-tertiary);font-size:10px;margin-right:4px;font-weight:600">' + (i + 1) + '</span>' +
      escHtml(v) +
      ' <button data-key="' + pipeKey + '" data-idx="' + i + '" onclick="removePipeTag(this)">&times;</button></span>';
  }).join('');
  initPipeDrag(pipeKey);
  renderPipePicker(pipeKey);
}

function togglePipeRouter(pipeKey, routerId) {
  var arr = _tags[pipeKey];
  var idx = arr.indexOf(routerId);
  if (idx !== -1) return;
  arr.push(routerId);
  renderPipeTags(pipeKey);
}

function removePipeTag(el) {
  var key = el.getAttribute('data-key');
  var idx = parseInt(el.getAttribute('data-idx'));
  if (key && _tags[key]) {
    _tags[key].splice(idx, 1);
    renderPipeTags(key);
  }
}

function initPipeDrag(pipeKey) {
  var container = document.getElementById('cfg-tags-' + pipeKey);
  if (!container) return;
  var tags = container.querySelectorAll('.pipe-tag');
  tags.forEach(function(tag) {
    tag.addEventListener('dragstart', function(e) {
      e.dataTransfer.setData('text/plain', tag.getAttribute('data-idx'));
      e.dataTransfer.effectAllowed = 'move';
      tag.classList.add('dragging');
    });
    tag.addEventListener('dragend', function() {
      tag.classList.remove('dragging');
    });
    tag.addEventListener('dragover', function(e) {
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
    });
    tag.addEventListener('drop', function(e) {
      e.preventDefault();
      var fromIdx = parseInt(e.dataTransfer.getData('text/plain'));
      var toIdx = parseInt(tag.getAttribute('data-idx'));
      if (isNaN(fromIdx) || isNaN(toIdx) || fromIdx === toIdx) return;
      var arr = _tags[pipeKey];
      var item = arr.splice(fromIdx, 1)[0];
      arr.splice(toIdx, 0, item);
      renderPipeTags(pipeKey);
    });
  });
}

function updateAvailableRouters() {
  renderPipeTags('pipe-um');
  renderPipeTags('pipe-tcp');
  renderPipeTags('pipe-tce');
}

function addCustomRouter() {
  var idInput = document.getElementById('new-router-id');
  var id = idInput.value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  if (!id) { showToast(t('cr.enter_id'), true); return; }
  if (_routers[id]) { showToast('"' + id + t('cr.exists'), true); return; }
  _routers[id] = {
    enabled: true,
    type: 'configurable',
    options: { keywords: { S2: [], S3: [] }, patterns: { S2: [], S3: [] }, prompt: '' }
  };
  idInput.value = '';
  renderCustomRouterCards();
  updateAvailableRouters();
  showToast('"' + id + t('cr.created'));
}

function removeCustomRouter(id) {
  if (!confirm(t('cr.del_pre') + id + t('cr.del_suf'))) return;
  delete _routers[id];
  // Clean up tag arrays
  delete _tags['cr-kw-s2-' + id];
  delete _tags['cr-kw-s3-' + id];
  delete _tags['cr-pat-s2-' + id];
  delete _tags['cr-pat-s3-' + id];

  // Save the removal to config
  var currentRouters = Object.assign({}, _routers);
  var payload = { privacy: { routers: currentRouters } };
  fetch(BASE + '/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }).then(function(r) { return r.json(); }).then(function(result) {
    if (result.ok) {
      showToast('"' + id + t('cr.deleted'));
      renderCustomRouterCards();
    } else {
      showToast(t('common.save_failed') + (result.error || 'unknown'), true);
    }
  }).catch(function(e) {
    showToast(t('common.save_failed') + e.message, true);
  });
}

async function saveCustomRouter(id) {
  try {
    var kwS2 = _tags['cr-kw-s2-' + id] || [];
    var kwS3 = _tags['cr-kw-s3-' + id] || [];
    var patS2 = _tags['cr-pat-s2-' + id] || [];
    var patS3 = _tags['cr-pat-s3-' + id] || [];
    var promptEl = document.getElementById('cr-prompt-' + id);
    var prompt = promptEl ? promptEl.value.trim() : '';
    var enabledEl = document.getElementById('cfg-cr-enabled-' + id);
    var enabled = enabledEl ? enabledEl.checked : true;

    var options = {
      keywords: { S2: kwS2, S3: kwS3 },
      patterns: { S2: patS2, S3: patS3 },
    };
    if (prompt) options.prompt = prompt;

    var currentRouters = Object.assign({}, _routers);
    currentRouters[id] = {
      enabled: enabled,
      type: 'configurable',
      options: options,
    };
    _routers[id] = currentRouters[id];

    var payload = { privacy: { routers: currentRouters } };
    var res = await fetch(BASE + '/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    var result = await res.json();
    if (result.ok) {
      showToast('"' + id + t('cr.saved'));
    } else {
      showToast(t('common.save_failed') + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast(t('common.save_failed') + e.message, true);
  }
}

// \u2500\u2500 Init \u2500\u2500
refreshAll();
loadConfig();
loadPresets();
loadPrompts();
setInterval(refreshAll, 30000);
if (LANG !== 'en') setLang(LANG);
</script>
</body>
</html>`;
}

// index.ts
var OPENCLAW_DIR2 = join5(process.env.HOME ?? "/tmp", ".openclaw");
var GUARDCLAW_CONFIG_PATH3 = join5(OPENCLAW_DIR2, "guardclaw.json");
var LEGACY_DASHBOARD_PATH = join5(OPENCLAW_DIR2, "guardclaw-dashboard.json");
function loadGuardClawConfigFile() {
  try {
    return JSON.parse(readFileSync3(GUARDCLAW_CONFIG_PATH3, "utf-8"));
  } catch {
    return null;
  }
}
function loadLegacyDashboardOverrides() {
  try {
    return JSON.parse(readFileSync3(LEGACY_DASHBOARD_PATH, "utf-8"));
  } catch {
    return null;
  }
}
function writeGuardClawConfigFile(config) {
  try {
    mkdirSync3(OPENCLAW_DIR2, { recursive: true });
    writeFileSync3(GUARDCLAW_CONFIG_PATH3, JSON.stringify(config, null, 2), "utf-8");
  } catch {
  }
}
function getPrivacyConfig3(pluginConfig) {
  const userConfig = pluginConfig?.privacy ?? {};
  return { ...defaultPrivacyConfig, ...userConfig };
}
function readApiKeyFromAuthProfiles(providerName) {
  const authPaths = [
    join5(OPENCLAW_DIR2, "agents", "main", "agent", "auth-profiles.json")
  ];
  for (const authPath of authPaths) {
    try {
      if (!existsSync3(authPath)) continue;
      const data = JSON.parse(readFileSync3(authPath, "utf-8"));
      const lastGoodKey = data.lastGood?.[providerName];
      if (lastGoodKey && data.profiles?.[lastGoodKey]?.key) {
        return data.profiles[lastGoodKey].key;
      }
      for (const profile of Object.values(data.profiles ?? {})) {
        if (profile.provider === providerName && profile.key) {
          return profile.key;
        }
      }
    } catch {
    }
  }
  return "";
}
function resolveProxyApi(originalApi) {
  const api = originalApi.toLowerCase();
  if (api.includes("google") || api.includes("gemini")) {
    return "openai-completions";
  }
  if (api === "anthropic-messages") {
    return "anthropic-messages";
  }
  return originalApi;
}
var plugin = {
  id: "guardclaw",
  name: "GuardClaw",
  description: "Privacy-aware plugin with extensible router pipeline, guard agent, and built-in privacy proxy",
  version: "2026.3.0",
  configSchema: guardClawConfigSchema,
  register(api) {
    let resolvedPluginConfig;
    const fileConfig = loadGuardClawConfigFile();
    if (fileConfig) {
      resolvedPluginConfig = fileConfig;
      api.logger.info("[GuardClaw] Config loaded from guardclaw.json");
    } else {
      const userPrivacy = (api.pluginConfig ?? {}).privacy;
      const legacyOverrides = loadLegacyDashboardOverrides();
      const mergedPrivacy = {
        ...defaultPrivacyConfig,
        ...userPrivacy ?? {},
        ...legacyOverrides ?? {}
      };
      if (legacyOverrides) {
        api.logger.info("[GuardClaw] Migrated legacy guardclaw-dashboard.json overrides");
      }
      resolvedPluginConfig = { privacy: mergedPrivacy };
      writeGuardClawConfigFile(resolvedPluginConfig);
      api.logger.info("[GuardClaw] Generated guardclaw.json with full defaults");
    }
    const privacyConfig = getPrivacyConfig3(resolvedPluginConfig);
    if (privacyConfig.enabled === false) {
      api.logger.info("[GuardClaw] Plugin disabled via config");
      return;
    }
    api.registerProvider(guardClawPrivacyProvider);
    const proxyPort = privacyConfig.proxyPort ?? 8403;
    if (!api.config.models) {
      api.config.models = { providers: {} };
    }
    const models = api.config.models;
    if (!models.providers) models.providers = {};
    const agentDefaults = api.config.agents?.defaults;
    const primaryModelStr = agentDefaults?.model?.primary ?? "";
    const defaultProvider = agentDefaults?.provider || primaryModelStr.split("/")[0] || "openai";
    const providerConfig = models.providers?.[defaultProvider];
    const originalApi = providerConfig?.api ?? "openai-completions";
    const proxyApi = resolveProxyApi(originalApi);
    const privacyProviderEntry = {
      baseUrl: `http://127.0.0.1:${proxyPort}/v1`,
      api: proxyApi,
      apiKey: "guardclaw-proxy-handles-auth",
      models: mirrorAllProviderModels(api.config, readApiKeyFromAuthProfiles)
    };
    models.providers["guardclaw-privacy"] = privacyProviderEntry;
    try {
      const runtimeCfg = api.runtime.config.loadConfig();
      if (runtimeCfg && runtimeCfg !== api.config) {
        if (!runtimeCfg.models) {
          runtimeCfg.models = { providers: {} };
        }
        const rtModels = runtimeCfg.models;
        if (!rtModels.providers) rtModels.providers = {};
        rtModels.providers["guardclaw-privacy"] = privacyProviderEntry;
      }
    } catch {
    }
    const mirroredModels = privacyProviderEntry.models;
    if (!agentDefaults) {
      const agts = api.config.agents;
      if (!agts.defaults) agts.defaults = {};
    }
    const ad = api.config.agents;
    const defs = ad.defaults;
    if (!defs.models) defs.models = {};
    const modelsOverridesRef = defs.models;
    for (const m of mirroredModels) {
      if (m.reasoning === true && typeof m.id === "string") {
        const proxyModelKey = `guardclaw-privacy/${m.id}`;
        const existing = modelsOverridesRef[proxyModelKey] ?? {};
        if (!existing.params || !existing.params.thinking) {
          modelsOverridesRef[proxyModelKey] = {
            ...existing,
            params: { ...existing.params ?? {}, thinking: "low" }
          };
        }
      }
    }
    try {
      const runtimeCfg2 = api.runtime.config.loadConfig();
      if (runtimeCfg2) {
        const rtAgts = runtimeCfg2.agents;
        const rtDefs = rtAgts?.defaults ?? {};
        if (!rtDefs.models) rtDefs.models = {};
        const rtMO = rtDefs.models;
        for (const m of mirroredModels) {
          if (m.reasoning === true && typeof m.id === "string") {
            const pk = `guardclaw-privacy/${m.id}`;
            const ex = rtMO[pk] ?? {};
            if (!ex.params || !ex.params.thinking) {
              rtMO[pk] = { ...ex, params: { ...ex.params ?? {}, thinking: "low" } };
            }
          }
        }
      }
    } catch {
    }
    const existingModelsOverrides = agentDefaults?.models ?? {};
    for (const [key, override] of Object.entries(existingModelsOverrides)) {
      if (override?.streaming === false) {
        const modelId = key.includes("/") ? key.split("/").slice(1).join("/") : key;
        const proxyKey = `guardclaw-privacy/${modelId}`;
        if (!existingModelsOverrides[proxyKey]) {
          existingModelsOverrides[proxyKey] = { streaming: false };
        }
      }
    }
    try {
      const runtimeCfg = api.runtime.config.loadConfig();
      if (runtimeCfg) {
        const rtAgents = runtimeCfg.agents;
        const rtDefaults = rtAgents?.defaults;
        if (rtDefaults) {
          const rtModelsOverrides = rtDefaults.models ?? {};
          for (const [key, override] of Object.entries(existingModelsOverrides)) {
            if (key.startsWith("guardclaw-privacy/")) {
              rtModelsOverrides[key] = override;
            }
          }
          rtDefaults.models = rtModelsOverrides;
        }
      }
    } catch {
    }
    if (providerConfig) {
      const defaultBaseUrl = resolveDefaultBaseUrl(defaultProvider, originalApi);
      const modelsOverrides = agentDefaults?.models ?? {};
      const modelStreamingPref = modelsOverrides[primaryModelStr]?.streaming;
      const apiKey = providerConfig.apiKey || readApiKeyFromAuthProfiles(defaultProvider);
      setDefaultProviderTarget({
        baseUrl: providerConfig.baseUrl ?? defaultBaseUrl,
        apiKey,
        provider: defaultProvider,
        api: originalApi,
        ...modelStreamingPref === false ? { streaming: false } : {}
      });
      if (apiKey) {
        api.logger.info(`[GuardClaw] Default proxy target: ${defaultProvider} (key: ${apiKey.slice(0, 8)}\u2026)`);
      } else {
        api.logger.warn(`[GuardClaw] No API key found for default provider ${defaultProvider} \u2014 proxy auth will fail`);
      }
    }
    api.logger.info(`[GuardClaw] Privacy provider registered (proxy port: ${proxyPort})`);
    const patchExtraPaths = (cfg) => {
      const agts = cfg.agents ?? {};
      const defs2 = agts.defaults ?? {};
      const ms = defs2.memorySearch ?? {};
      const existing = ms.extraPaths ?? [];
      const requiredPaths = ["MEMORY-FULL.md", "memory-full"];
      const missing = requiredPaths.filter((p) => !existing.includes(p));
      if (missing.length === 0) return false;
      const updated = [...existing, ...missing];
      if (!cfg.agents) cfg.agents = { defaults: {} };
      const a = cfg.agents;
      if (!a.defaults) a.defaults = {};
      const d2 = a.defaults;
      if (!d2.memorySearch) d2.memorySearch = {};
      d2.memorySearch.extraPaths = updated;
      return true;
    };
    if (patchExtraPaths(api.config)) {
      api.logger.info(`[GuardClaw] Added to memorySearch.extraPaths: MEMORY-FULL.md, memory-full`);
    }
    try {
      const runtimeCfg = api.runtime.config.loadConfig();
      if (runtimeCfg && runtimeCfg !== api.config) {
        patchExtraPaths(runtimeCfg);
      }
    } catch {
    }
    let proxyHandle = null;
    api.registerService({
      id: "guardclaw-proxy",
      start: async () => {
        try {
          proxyHandle = await startPrivacyProxy(proxyPort, api.logger);
          setActiveProxy(proxyHandle);
          api.logger.info(`[GuardClaw] Privacy proxy started on port ${proxyPort}`);
        } catch (err) {
          api.logger.error(`[GuardClaw] Failed to start privacy proxy: ${String(err)}`);
        }
      },
      stop: async () => {
        if (proxyHandle) {
          try {
            await proxyHandle.close();
            api.logger.info("[GuardClaw] Privacy proxy stopped");
          } catch (err) {
            api.logger.warn(`[GuardClaw] Failed to close proxy: ${String(err)}`);
          }
        }
      }
    });
    const pipeline = new RouterPipeline(api.logger);
    const routerConfigs = privacyConfig.routers;
    pipeline.register(privacyRouter, routerConfigs?.privacy ?? { enabled: true, type: "builtin" });
    pipeline.register(tokenSaverRouter, routerConfigs?.["token-saver"] ?? { enabled: false, type: "builtin" });
    pipeline.configure({
      routers: routerConfigs,
      pipeline: privacyConfig.pipeline
    });
    pipeline.loadCustomRouters().then(() => {
      const routers = pipeline.listRouters();
      if (routers.length > 1) {
        api.logger.info(`[GuardClaw] Pipeline routers: ${routers.join(", ")}`);
      }
    }).catch((err) => {
      api.logger.error(`[GuardClaw] Failed to load custom routers: ${String(err)}`);
    });
    setGlobalPipeline(pipeline);
    api.logger.info(`[GuardClaw] Router pipeline initialized (built-in: privacy)`);
    initLiveConfig(resolvedPluginConfig);
    watchConfigFile(GUARDCLAW_CONFIG_PATH3, api.logger);
    const statsPath = join5(process.env.HOME ?? "/tmp", ".openclaw", "guardclaw-stats.json");
    const collector = new TokenStatsCollector(statsPath);
    setGlobalCollector(collector);
    collector.load().then(() => {
      collector.startAutoFlush();
      api.logger.info(`[GuardClaw] Token stats initialized (${statsPath})`);
    }).catch((err) => {
      api.logger.error(`[GuardClaw] Failed to load token stats: ${String(err)}`);
    });
    initDashboard({
      pluginId: "guardclaw",
      pluginConfig: resolvedPluginConfig,
      pipeline
    });
    api.registerHttpRoute({
      path: "/plugins/guardclaw/stats",
      auth: "plugin",
      match: "prefix",
      handler: async (req, res) => {
        const handled = await statsHttpHandler(req, res);
        if (!handled) {
          res.writeHead(404);
          res.end("Not Found");
        }
      }
    });
    api.logger.info("[GuardClaw] Dashboard registered at /plugins/guardclaw/stats");
    registerHooks(api);
    api.logger.info("[GuardClaw] Plugin initialized (pipeline + privacy proxy + guard agent + dashboard)");
    const c = "\x1B[36m", g = "\x1B[32m", y = "\x1B[33m", b = "\x1B[1m", d = "\x1B[2m", r = "\x1B[0m", bg = "\x1B[46m\x1B[30m";
    const W = 70;
    const bar = "\u2550".repeat(W);
    const pad = (colored, visLen) => {
      const sp = " ".repeat(Math.max(0, W - visLen));
      return `${c}  \u2551${r}${colored}${sp}${c}\u2551${r}`;
    };
    api.logger.info("");
    api.logger.info(`${c}  \u2554${bar}\u2557${r}`);
    api.logger.info(pad(`  ${bg}${b} \u{1F6E1}\uFE0F  GuardClaw ${r}${g}${b}  Ready!${r}`, 25));
    api.logger.info(pad("", 0));
    api.logger.info(pad(`  ${y}Dashboard${r} ${d}\u2192${r}  ${b}http://127.0.0.1:18789/plugins/guardclaw/stats${r}`, 62));
    api.logger.info(pad(`  ${y}Config${r}    ${d}\u2192${r}  ${b}~/.openclaw/guardclaw.json${r}`, 40));
    api.logger.info(pad("", 0));
    api.logger.info(pad(`  ${d}Use the Dashboard to configure routers, rules & prompts.${r}`, 58));
    api.logger.info(`${c}  \u255A${bar}\u255D${r}`);
    api.logger.info("");
  }
};
var index_default = plugin;
export {
  index_default as default,
  writeGuardClawConfigFile
};
