import {
  DEFAULT_DETECTION_SYSTEM_PROMPT,
  DEFAULT_LOCAL_CLASSIFIER_MODEL,
  DEFAULT_PII_EXTRACTION_PROMPT,
  SECURITY_CHANNEL,
  TokenStatsCollector,
  addCorrection,
  appendToRollingBuffer,
  callChatCompletion,
  clearActiveLocalRouting,
  clearLastSenderId,
  clearSessionState,
  consumeDetection,
  defaultInjectionConfig,
  defaultPrivacyConfig,
  deleteCorrection,
  desensitizeWithLocalModel,
  detectByLocalModel,
  detectInjection,
  finalizeLoop,
  formatBlockAlert,
  getAllSessionStates,
  getCorrections,
  getCurrentLoopHighestLevel,
  getGlobalCollector,
  getLastReplyLoopSummary,
  getLastReplyModelOrigin,
  getLastSenderId,
  getLastTurnTokens,
  getLiveConfig,
  getLiveInjectionConfig,
  getPendingDetection,
  guardClawConfigSchema,
  initInjectionConfig,
  initLiveConfig,
  isActiveLocalRouting,
  isSessionMarkedPrivate,
  levelToNumeric,
  loadInjectionAttemptCounts,
  loadPrompt,
  loadPromptWithVars,
  markSessionAsPrivate,
  maxLevel,
  pendingBans,
  readPromptFromDisk,
  recordDetection,
  recordFinalReply,
  recordInjectionAttempt,
  resetTurnLevel,
  runDebertaClassifier,
  runHeuristics,
  sanitiseContent,
  setActiveLocalRouting,
  setGlobalCollector,
  setLastSenderId,
  stashDetection,
  trackSessionLevel,
  triggerDebertaReload,
  updateLiveConfig,
  updateLiveInjectionConfig,
  watchConfigFile,
  withConfigWriteLock,
  writePrompt
} from "./chunk-6JG7VSVH.js";
import {
  fireWebhooks
} from "./chunk-DLV362LL.js";

// index.ts
import { join as join12 } from "path";
import { readFileSync as readFileSync3, writeFileSync as writeFileSync3, mkdirSync as mkdirSync3, existsSync as existsSync3 } from "fs";

// src/hooks.ts
import * as fs4 from "fs";
import * as path3 from "path";
import { join as join8 } from "path";

// src/guard-agent.ts
function isGuardAgentConfigured(config) {
  return Boolean(config.guardAgent?.provider);
}
function getGuardAgentConfig(config) {
  if (!isGuardAgentConfigured(config)) {
    return null;
  }
  return {
    id: config.guardAgent?.id ?? "guard",
    workspace: config.guardAgent?.workspace ?? "~/.openclaw/workspace-guard",
    provider: config.guardAgent.provider,
    modelName: config.guardAgent?.model || void 0
  };
}
function isGuardSessionKey(sessionKey2) {
  return sessionKey2.endsWith(":guard") || sessionKey2.includes(":guard:");
}
var registeredGuardParents = /* @__PURE__ */ new Set();
function registerGuardSessionParent(parentSessionKey) {
  registeredGuardParents.add(parentSessionKey);
}
function isVerifiedGuardSession(sessionKey2) {
  if (!isGuardSessionKey(sessionKey2)) return false;
  const idx = sessionKey2.indexOf(":guard");
  if (idx === -1) return false;
  const parentKey = sessionKey2.slice(0, idx);
  return registeredGuardParents.has(parentKey);
}
function deregisterGuardSession(sessionKey2) {
  const idx = sessionKey2.indexOf(":guard");
  if (idx !== -1) registeredGuardParents.delete(sessionKey2.slice(0, idx));
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

// src/synthesis.ts
var DEFAULT_SYNTHESIS_PROMPT = `You are a privacy-preserving content transformer. Re-express the content below so it conveys the information needed for the user's task, but contains NO sensitive values (no passwords, keys, tokens, credentials, or raw personal data). Describe sensitive values by type only \u2014 e.g. "[API key]", "[password]", "[RSA private key]". Preserve all structural context (file paths, variable names, config keys, non-sensitive values). Output ONLY the transformed content \u2014 no preamble.

User task context:
{{TASK_CONTEXT}}

Content to transform:
{{CONTENT}}`;
var DEFAULT_VERIFY_PROMPT = `Does the following text contain any sensitive values that should not be sent to a cloud AI? (passwords, API keys, tokens, private keys, raw credentials \u2014 NOT type descriptions like "[API key]" or "[password]"). Respond ONLY with JSON: {"safe":true} or {"safe":false,"reason":"..."}.

Text:
{{CONTENT}}`;
var DEFAULT_CONFIG = {
  fallback: "local-only",
  verifyOutput: true,
  maxRetries: 2,
  maxInputChars: 4e3,
  timeoutMs: 2e4
};
function resolveConfig(config) {
  const s = config.synthesis;
  return {
    fallback: s?.fallback ?? DEFAULT_CONFIG.fallback,
    verifyOutput: s?.verifyOutput ?? DEFAULT_CONFIG.verifyOutput,
    maxRetries: s?.maxRetries ?? DEFAULT_CONFIG.maxRetries,
    maxInputChars: s?.maxInputChars ?? DEFAULT_CONFIG.maxInputChars,
    timeoutMs: s?.timeoutMs ?? DEFAULT_CONFIG.timeoutMs
  };
}
async function callSynthesis(content, taskContext, config, timeoutMs) {
  const endpoint = config.localModel?.endpoint ?? "http://localhost:11434";
  const model = config.localModel?.model ?? DEFAULT_LOCAL_CLASSIFIER_MODEL;
  const providerType = config.localModel?.type ?? "openai-compatible";
  const prompt = loadPromptWithVars("s3-synthesis", DEFAULT_SYNTHESIS_PROMPT, {
    CONTENT: content,
    TASK_CONTEXT: taskContext || "General assistance"
  });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const result = await callChatCompletion(
      endpoint,
      model,
      [{ role: "user", content: prompt }],
      {
        temperature: 0.15,
        maxTokens: 1200,
        providerType,
        apiKey: config.localModel?.apiKey,
        customModule: config.localModel?.module,
        disableThinking: true
      }
    );
    return result.text.trim();
  } finally {
    clearTimeout(timer);
  }
}
async function verifySynthesis(synthetic, config, timeoutMs) {
  const endpoint = config.localModel?.endpoint ?? "http://localhost:11434";
  const model = config.localModel?.model ?? DEFAULT_LOCAL_CLASSIFIER_MODEL;
  const providerType = config.localModel?.type ?? "openai-compatible";
  const prompt = loadPromptWithVars("s3-verify", DEFAULT_VERIFY_PROMPT, {
    CONTENT: synthetic.slice(0, 2e3)
  });
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let raw;
    try {
      const result = await callChatCompletion(
        endpoint,
        model,
        [{ role: "user", content: prompt }],
        {
          temperature: 0,
          maxTokens: 80,
          stop: ["\n\n"],
          providerType,
          apiKey: config.localModel?.apiKey,
          customModule: config.localModel?.module,
          disableThinking: true
        }
      );
      raw = result.text.trim();
    } finally {
      clearTimeout(timer);
    }
    const match = raw.match(/\{[\s\S]*?\}/);
    if (match) {
      const parsed = JSON.parse(match[0]);
      return { safe: parsed.safe !== false, reason: parsed.reason };
    }
    return { safe: true };
  } catch {
    return { safe: true };
  }
}
async function synthesizeContent(original, taskContext, config, sessionKey2) {
  if (!config.localModel?.enabled) {
    return { ok: false, reason: "Local model not enabled" };
  }
  const cfg = resolveConfig(config);
  const input = original.slice(0, cfg.maxInputChars);
  let lastFailReason = "Unknown error";
  for (let attempt = 0; attempt <= cfg.maxRetries; attempt++) {
    try {
      const synthetic = await callSynthesis(input, taskContext, config, cfg.timeoutMs);
      if (!synthetic) {
        lastFailReason = "Empty synthesis output";
        continue;
      }
      if (cfg.verifyOutput) {
        const { safe, reason } = await verifySynthesis(synthetic, config, Math.min(cfg.timeoutMs, 8e3));
        if (!safe) {
          lastFailReason = `Verification failed: ${reason ?? "S3 content detected in output"}`;
          console.warn(`[GuardClaw Synthesis] Attempt ${attempt + 1} failed verification \u2014 retrying`);
          continue;
        }
      }
      const finalSynthetic = input.length < original.length ? `${synthetic}

[Note: input was truncated to ${cfg.maxInputChars} characters for local processing]` : synthetic;
      return { ok: true, synthetic: finalSynthetic };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      lastFailReason = message.includes("abort") ? "Synthesis timeout" : message;
      console.warn(`[GuardClaw Synthesis] Attempt ${attempt + 1} error: ${lastFailReason}`);
    }
  }
  return { ok: false, reason: lastFailReason };
}
async function synthesizeToolResult(toolName, toolResult, taskContext, config, sessionKey2) {
  if (!config.localModel?.enabled) {
    return { ok: false, reason: "Local model not enabled" };
  }
  const cfg = resolveConfig(config);
  const toolContext = `Tool "${toolName}" returned a result. Task context: ${taskContext || "general assistance"}`;
  const input = toolResult.slice(0, cfg.maxInputChars);
  return synthesizeContent(input, toolContext, config, sessionKey2);
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
function extractPathsFromParams(params2, _depth = 0) {
  if (_depth > 5) return [];
  const paths = [];
  const pathKeys = ["path", "file", "filepath", "filename", "dir", "directory", "target", "source"];
  for (const key of pathKeys) {
    const value = params2[key];
    if (typeof value === "string" && value.trim()) {
      paths.push(value.trim());
    }
  }
  const commandKeys = ["command", "cmd", "script"];
  for (const key of commandKeys) {
    const value = params2[key];
    if (typeof value === "string" && value.trim()) {
      paths.push(...extractPathsFromCommand(value));
    }
  }
  for (const value of Object.values(params2)) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      paths.push(...extractPathsFromParams(value, _depth + 1));
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
function redactForCleanTranscript(text, userOpts) {
  return redactSensitiveInfo(text, {
    internalIp: true,
    email: true,
    envVar: true,
    creditCard: true,
    chinesePhone: true,
    chineseId: true,
    chineseAddress: true,
    pin: true,
    ...userOpts
  });
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
var CLEAN_MEMORY_MAX_CHARS = 4e3;
var FULL_MEMORY_MAX_CHARS = 6e3;
function truncateKeepRecent(content, maxChars) {
  if (content.length <= maxChars) return content;
  const lines = content.split("\n");
  const headerLines = lines.slice(0, 3);
  const bodyLines = lines.slice(3);
  const headerSize = headerLines.join("\n").length + 1;
  const budget = maxChars - headerSize;
  const kept = [];
  let size = 0;
  for (let i = bodyLines.length - 1; i >= 0; i--) {
    const lineSize = bodyLines[i].length + 1;
    if (size + lineSize > budget) break;
    kept.unshift(bodyLines[i]);
    size += lineSize;
  }
  return [...headerLines, ...kept].join("\n");
}
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
        await fs.promises.appendFile(filePath, content, { encoding: "utf-8", mode: 384 });
      } else {
        await fs.promises.writeFile(filePath, content, { encoding: "utf-8", mode: 384 });
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
      const merged = truncateKeepRecent(fullContent + appendBlock, FULL_MEMORY_MAX_CHARS);
      await this.writeMemory(merged, false, options);
      console.log(`[GuardClaw] Merged ${newLines.length} line(s) from clean \u2192 full (${merged.length} chars)`);
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
      const cappedClean = truncateKeepRecent(cleanMemory, CLEAN_MEMORY_MAX_CHARS);
      if (cappedClean.length < cleanMemory.length) {
        console.log(`[GuardClaw] MEMORY.md capped: ${cleanMemory.length} \u2192 ${cappedClean.length} chars`);
      }
      await this.writeMemory(cappedClean, true);
      const writtenClean = await this.readMemory(true);
      if (writtenClean.includes(GUARD_SECTION_BEGIN)) {
        console.warn("[GuardClaw] INTEGRITY: GUARD_SECTION_BEGIN found in MEMORY.md after sync \u2014 re-filtering");
        const reFiltered = this.filterGuardContent(writtenClean);
        if (reFiltered.includes(GUARD_SECTION_BEGIN)) {
          console.error("[GuardClaw] INTEGRITY: re-filter failed to remove guard markers \u2014 clearing MEMORY.md as safety fallback");
          await this.writeMemory("", true);
        } else {
          await this.writeMemory(reFiltered, true);
        }
      }
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
          await fs.promises.writeFile(cleanPath, cleanContent, { encoding: "utf-8", mode: 384 });
          if (cleanContent.includes(GUARD_SECTION_BEGIN)) {
            console.warn(`[GuardClaw] INTEGRITY: GUARD_SECTION_BEGIN in daily clean file ${file} \u2014 re-filtering`);
            const reFiltered = this.filterGuardContent(cleanContent);
            await fs.promises.writeFile(cleanPath, reFiltered, { encoding: "utf-8", mode: 384 });
          }
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
   * Sync everything: long-term memory + all daily files.
   *
   * GCF-025: Uses an O_EXCL advisory lock file (~/.openclaw/memory-sync.lock)
   * to prevent concurrent syncAllMemoryToClean() calls (e.g. from two sessions
   * both reaching session_end at the same time) from producing TOCTOU races on
   * MEMORY.md / MEMORY-FULL.md. Non-blocking: if the lock is already held,
   * this call is skipped and a warning is logged rather than waiting.
   */
  async syncAllMemoryToClean(privacyConfig) {
    const lockDir = path.join(
      process.env.HOME || process.env.USERPROFILE || "/tmp",
      ".openclaw"
    );
    const lockPath = path.join(lockDir, "memory-sync.lock");
    let lockFd = null;
    try {
      await fs.promises.mkdir(lockDir, { recursive: true });
      lockFd = await fs.promises.open(
        lockPath,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
        384
      );
    } catch {
      console.warn("[GuardClaw] Memory sync skipped: lock held by another process");
      return;
    }
    try {
      await this.syncMemoryToClean(privacyConfig);
      await this.syncDailyMemoryToClean(privacyConfig);
    } finally {
      if (lockFd) {
        await lockFd.close();
        await fs.promises.unlink(lockPath).catch(() => {
        });
      }
    }
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
      await fs.promises.writeFile(fullPath, fullContent + appendBlock, { encoding: "utf-8", mode: 384 });
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
var DualSessionManager = class _DualSessionManager {
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
  async persistMessage(sessionKey2, message, agentId = "main") {
    await this.writeToHistory(sessionKey2, message, agentId, "full");
    if (!this.isGuardAgentMessage(message)) {
      await this.writeToHistory(sessionKey2, message, agentId, "clean");
    }
  }
  /**
   * Seed the full track with existing clean track content (if any) so that
   * the full track is a complete history from the start of the session.
   * No-op if the full track already exists.  Mirrors the memory-isolation
   * pattern of mergeCleanIntoFull.
   */
  seededSessions = /* @__PURE__ */ new Set();
  async ensureFullTrackSeeded(sessionKey2, agentId) {
    const key = `${sessionKey2}:${agentId}`;
    if (this.seededSessions.has(key)) return;
    const fullPath = this.getHistoryPath(sessionKey2, agentId, "full");
    if (fs2.existsSync(fullPath)) {
      this.seededSessions.add(key);
      return;
    }
    const cleanPath = this.getHistoryPath(sessionKey2, agentId, "clean");
    if (!fs2.existsSync(cleanPath)) {
      this.seededSessions.add(key);
      return;
    }
    try {
      const dir = path2.dirname(fullPath);
      await fs2.promises.mkdir(dir, { recursive: true });
      await fs2.promises.copyFile(cleanPath, fullPath);
      console.log(`[GuardClaw] Seeded full track from clean track for ${sessionKey2}`);
    } catch (err) {
      console.error(`[GuardClaw] Failed to seed full track for ${sessionKey2}:`, err);
    }
    this.seededSessions.add(key);
  }
  /**
   * Write a message to the full history only.
   * On first write, seeds the full track with existing clean track content
   * so it contains the complete conversation history.
   */
  async writeToFull(sessionKey2, message, agentId = "main") {
    await this.ensureFullTrackSeeded(sessionKey2, agentId);
    await this.writeToHistory(sessionKey2, message, agentId, "full");
  }
  /**
   * Write a message to the clean history only.
   */
  async writeToClean(sessionKey2, message, agentId = "main") {
    await this.writeToHistory(sessionKey2, message, agentId, "clean");
  }
  /**
   * Load session history based on model type
   * - Cloud models: get clean history only
   * - Local models: get full history
   */
  async loadHistory(sessionKey2, isCloudModel, agentId = "main", limit) {
    const historyType = isCloudModel ? "clean" : "full";
    return await this.readHistory(sessionKey2, agentId, historyType, limit);
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
  /** Max session file size in bytes before auto-trim (default: 5MB) */
  static MAX_FILE_BYTES = 5 * 1024 * 1024;
  /** Lines to keep when trimming */
  static TRIM_KEEP_LINES = 1e3;
  /** Track which files we've checked this process lifetime to avoid repeated stat calls */
  trimChecked = /* @__PURE__ */ new Set();
  /**
   * Write message to history file.
   * Uses a per-file write lock to serialize concurrent appends
   * (e.g. from fire-and-forget calls in sync hooks).
   * Auto-trims files that exceed MAX_FILE_BYTES.
   */
  async writeToHistory(sessionKey2, message, agentId, historyType) {
    const historyPath = this.getHistoryPath(sessionKey2, agentId, historyType);
    await this.withWriteLock(historyPath, async () => {
      try {
        const dir = path2.dirname(historyPath);
        await fs2.promises.mkdir(dir, { recursive: true });
        const line = JSON.stringify({
          ...message,
          timestamp: message.timestamp ?? Date.now()
        });
        await fs2.promises.appendFile(historyPath, line + "\n", { encoding: "utf-8", mode: 384 });
        await this.maybeAutoTrim(historyPath);
      } catch (err) {
        console.error(
          `[GuardClaw] Failed to write to ${historyType} history for ${sessionKey2}:`,
          err
        );
      }
    });
  }
  /** Trim file to last TRIM_KEEP_LINES if it exceeds MAX_FILE_BYTES */
  async maybeAutoTrim(filePath) {
    try {
      const stat = await fs2.promises.stat(filePath);
      if (stat.size <= _DualSessionManager.MAX_FILE_BYTES) {
        return;
      }
      const content = await fs2.promises.readFile(filePath, "utf-8");
      const lines = content.trim().split("\n");
      if (lines.length <= _DualSessionManager.TRIM_KEEP_LINES) return;
      const trimmed = lines.slice(-_DualSessionManager.TRIM_KEEP_LINES).join("\n") + "\n";
      await fs2.promises.writeFile(filePath, trimmed, { encoding: "utf-8", mode: 384 });
      const savedMB = ((stat.size - Buffer.byteLength(trimmed)) / (1024 * 1024)).toFixed(1);
      console.log(`[GuardClaw] Auto-trimmed ${path2.basename(filePath)}: ${lines.length} \u2192 ${_DualSessionManager.TRIM_KEEP_LINES} lines (freed ${savedMB}MB)`);
    } catch {
    }
  }
  /**
   * Read messages from history file
   */
  async readHistory(sessionKey2, agentId, historyType, limit) {
    try {
      const historyPath = this.getHistoryPath(sessionKey2, agentId, historyType);
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
        `[GuardClaw] Failed to read ${historyType} history for ${sessionKey2}:`,
        err
      );
      return [];
    }
  }
  /**
   * Get history file path
   */
  getHistoryPath(sessionKey2, agentId, historyType) {
    const safeSessionKey = sessionKey2.replace(/[^a-zA-Z0-9_-]/g, "_");
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
  async clearHistory(sessionKey2, agentId = "main", historyType) {
    const types = historyType ? [historyType] : ["full", "clean"];
    for (const type of types) {
      try {
        const historyPath = this.getHistoryPath(sessionKey2, agentId, type);
        if (fs2.existsSync(historyPath)) {
          await fs2.promises.unlink(historyPath);
        }
      } catch (err) {
        console.error(
          `[GuardClaw] Failed to clear ${type} history for ${sessionKey2}:`,
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
  async loadHistoryDelta(sessionKey2, agentId = "main", limit) {
    const full = await this.readHistory(sessionKey2, agentId, "full");
    const clean = await this.readHistory(sessionKey2, agentId, "clean");
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
  async getHistoryStats(sessionKey2, agentId = "main") {
    const full = await this.readHistory(sessionKey2, agentId, "full");
    const clean = await this.readHistory(sessionKey2, agentId, "clean");
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
function normalizeForDetection(text) {
  const nfkd = text.normalize("NFKD").replace(new RegExp("\\p{Mn}", "gu"), "");
  return nfkd.replace(/@/g, "a").replace(/0/g, "o").replace(/3/g, "e").replace(/1/g, "i").replace(/\$/g, "s").replace(/5/g, "s");
}
var PATTERN_CACHE_MAX = 500;
var PATTERN_MAX_LENGTH = 500;
var patternCache = /* @__PURE__ */ new Map();
function isDangerousRegex(pattern) {
  if (/\((?:\?:)?[^)]*[+*?]\)[+*?{]/.test(pattern)) return true;
  if (/\([^)]*\|[^)]*\)[+*{]/.test(pattern)) return true;
  if (/\([^)]*\{\d+,\d*\}[^)]*\)[+*?{]/.test(pattern)) return true;
  if (/\((?:\?:)?[^)]*\[[^\]]+\][+*?][^)]*\)[+*?{]/.test(pattern)) return true;
  if (/\([^)]*[+*?][^)]*\|[^)]*[+*?][^)]*\)[+*?{]/.test(pattern)) return true;
  if (/\(\.[*+]\)[+*?{]/.test(pattern)) return true;
  if (/\([^)]*\|\)[+*{]/.test(pattern)) return true;
  if (/\(\|[^)]*\)[+*{]/.test(pattern)) return true;
  if (/\(\?:[^)]*\|[^)]*[*+][^)]*\)[+*?{]/.test(pattern)) return true;
  return false;
}
function getOrCompileRegex(pattern) {
  const cached = patternCache.get(pattern);
  if (cached) return cached;
  if (pattern.length > PATTERN_MAX_LENGTH) {
    console.warn(`[GuardClaw] Regex pattern too long (${pattern.length} > ${PATTERN_MAX_LENGTH}), skipping`);
    return null;
  }
  if (isDangerousRegex(pattern)) {
    console.warn(`[GuardClaw] Potentially dangerous regex pattern rejected (nested quantifiers): ${pattern.slice(0, 80)}`);
    return null;
  }
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
  const normalized = normalizeForDetection(text);
  const s3Keywords = config.rules?.keywords?.S3 ?? [];
  for (const keyword of s3Keywords) {
    if (getKeywordRegex(keyword).test(normalized)) {
      return {
        level: "S3",
        reason: `S3 keyword detected: ${keyword}`
      };
    }
  }
  const s2Keywords = config.rules?.keywords?.S2 ?? [];
  for (const keyword of s2Keywords) {
    if (getKeywordRegex(keyword).test(normalized)) {
      return {
        level: "S2",
        reason: `S2 keyword detected: ${keyword}`
      };
    }
  }
  return { level: "S1" };
}
function checkPatterns(text, config) {
  const normalized = normalizeForDetection(text);
  const s3Patterns = config.rules?.patterns?.S3 ?? [];
  for (const pattern of s3Patterns) {
    const regex = getOrCompileRegex(pattern);
    if (regex && regex.test(normalized)) {
      return {
        level: "S3",
        reason: `S3 pattern matched: ${pattern}`
      };
    }
  }
  const s2Patterns = config.rules?.patterns?.S2 ?? [];
  for (const pattern of s2Patterns) {
    const regex = getOrCompileRegex(pattern);
    if (regex && regex.test(normalized)) {
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
function checkToolParams(params2, config) {
  const paths = extractPathsFromParams(params2);
  if (paths.length === 0) {
    return { level: "S1" };
  }
  for (const path4 of paths) {
    if (path4.startsWith("/run/secrets/") || path4.startsWith("/var/run/secrets/")) {
      return {
        level: "S2",
        reason: `Docker/Kubernetes secrets mount detected: ${path4}`
      };
    }
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
import * as fs3 from "fs";
import { join as join3 } from "path";

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
var PROVIDER_STASH_MAX = 500;
var originalProviderTargets = /* @__PURE__ */ new Map();
function stashOriginalProvider(key, target) {
  if (originalProviderTargets.size >= PROVIDER_STASH_MAX) {
    const oldest = originalProviderTargets.keys().next().value;
    if (oldest !== void 0) originalProviderTargets.delete(oldest);
  }
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
var _OPENCLAW_DIR = join3(process.env.HOME ?? "/tmp", ".openclaw");
var GUARDCLAW_INJECTIONS_PATH = join3(_OPENCLAW_DIR, "guardclaw-injections.json");
var GUARDCLAW_JSON_PATH = join3(_OPENCLAW_DIR, "guardclaw.json");
async function appendProxyInjectionLog(entry) {
  let entries = [];
  try {
    const raw = await fs3.promises.readFile(GUARDCLAW_INJECTIONS_PATH, "utf8");
    try {
      const parsed = JSON.parse(raw);
      entries = Array.isArray(parsed) ? parsed : [];
    } catch {
    }
  } catch {
  }
  entries.push(entry);
  if (entries.length > 200) entries = entries.slice(entries.length - 200);
  try {
    await fs3.promises.writeFile(GUARDCLAW_INJECTIONS_PATH, JSON.stringify(entries, null, 2));
  } catch (err) {
    console.warn(`[GuardClaw S0] Failed to write proxy injection log: ${String(err)}`);
  }
}
var defaultProviderTarget = null;
function setDefaultProviderTarget(target) {
  defaultProviderTarget = target;
}
function readRequestBody(req) {
  return new Promise((resolve3, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve3(Buffer.concat(chunks).toString("utf-8")));
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
    const params2 = fn?.parameters;
    if (params2 && typeof params2 === "object") {
      const result = stripUnsupportedSchemaKeywords(params2);
      if (result !== params2) {
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
      const params2 = decl.parameters;
      if (params2 && typeof params2 === "object") {
        decl.parameters = stripUnsupportedSchemaKeywords(params2);
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
      const extracted = msg.content.slice(openIdx + GUARDCLAW_S2_OPEN.length, closeIdx).trim();
      if (!extracted) continue;
      msg.content = extracted;
      stripped = true;
    } else if (Array.isArray(msg.content)) {
      for (const part of msg.content) {
        if (!part || typeof part.text !== "string") continue;
        const openIdx = part.text.indexOf(GUARDCLAW_S2_OPEN);
        const closeIdx = part.text.indexOf(GUARDCLAW_S2_CLOSE);
        if (openIdx === -1 || closeIdx === -1 || closeIdx <= openIdx) continue;
        const extracted = part.text.slice(openIdx + GUARDCLAW_S2_OPEN.length, closeIdx).trim();
        if (!extracted) continue;
        part.text = extracted;
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
var OLLAMA_APIS = ["ollama"];
var OLLAMA_URL_MARKERS = [":11434"];
function isOllamaTarget(target) {
  const api = (target.api ?? "").toLowerCase();
  const provider = target.provider.toLowerCase();
  const url = target.baseUrl.toLowerCase();
  const OPENAI_COMPAT_APIS = ["openai-completions", "openai-chat", "openai"];
  if (OPENAI_COMPAT_APIS.includes(api)) return false;
  if (OLLAMA_APIS.includes(api)) return true;
  if (provider.includes("ollama")) return true;
  if (OLLAMA_URL_MARKERS.some((p) => url.includes(p))) return true;
  return false;
}
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
  if (isOllamaTarget(target)) return headers;
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
  let baseUrl = targetBaseUrl;
  while (baseUrl.endsWith("/")) baseUrl = baseUrl.slice(0, -1);
  const rawPath = reqUrl ?? "/v1/chat/completions";
  const api = (target?.api ?? "").toLowerCase();
  const isAnthropic = api === "anthropic-messages" || ANTHROPIC_PATTERNS.some((p) => (target?.provider ?? "").toLowerCase().includes(p));
  if (isAnthropic) {
    return `${baseUrl}${rawPath}`;
  }
  if (target && isOllamaTarget(target)) {
    const ollamaBase = baseUrl.replace(/\/v1$/, "");
    if (rawPath.includes("/chat/completions") || rawPath.includes("/chat")) {
      return `${ollamaBase}/api/chat`;
    }
    return `${ollamaBase}/api${rawPath.replace(/^\/v1/, "")}`;
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
var CIRCUIT_FAILURE_THRESHOLD = 3;
var CIRCUIT_COOLDOWN_MS = 3e4;
var circuitBreakers = /* @__PURE__ */ new Map();
function getCircuit(key) {
  let entry = circuitBreakers.get(key);
  if (!entry) {
    entry = { state: "closed", failures: 0, lastFailure: 0, lastSuccess: 0 };
    circuitBreakers.set(key, entry);
  }
  if (entry.state === "open" && Date.now() - entry.lastFailure > CIRCUIT_COOLDOWN_MS) {
    entry.state = "half-open";
  }
  return entry;
}
function recordUpstreamSuccess(key) {
  const entry = getCircuit(key);
  entry.state = "closed";
  entry.failures = 0;
  entry.lastSuccess = Date.now();
}
function recordUpstreamFailure(key) {
  const entry = getCircuit(key);
  entry.failures++;
  entry.lastFailure = Date.now();
  if (entry.failures >= CIRCUIT_FAILURE_THRESHOLD) {
    entry.state = "open";
    return true;
  }
  return false;
}
function isCircuitOpen(key) {
  return getCircuit(key).state === "open";
}
var Semaphore = class {
  constructor(_max) {
    this._max = _max;
  }
  _current = 0;
  _queue = [];
  async acquire(timeoutMs) {
    if (this._current < this._max) {
      this._current++;
      return true;
    }
    return new Promise((resolve3) => {
      const timer = setTimeout(() => {
        const idx = this._queue.indexOf(cb);
        if (idx !== -1) this._queue.splice(idx, 1);
        resolve3(false);
      }, timeoutMs);
      const cb = () => {
        clearTimeout(timer);
        this._current++;
        resolve3(true);
      };
      this._queue.push(cb);
    });
  }
  release() {
    this._current--;
    if (this._queue.length > 0) {
      const next = this._queue.shift();
      next();
    }
  }
  get active() {
    return this._current;
  }
  get queued() {
    return this._queue.length;
  }
};
var DEFAULT_PROXY_CONCURRENCY = 5;
var SEMAPHORE_TIMEOUT_MS = 1e4;
async function startPrivacyProxy(port, logger) {
  const log = logger ?? {
    info: (m) => console.log(m),
    warn: (m) => console.warn(m),
    error: (m) => console.error(m)
  };
  const logDebug = (m) => {
    if (getLiveConfig().debugLogging) log.info(m);
  };
  const proxyConcurrency = getLiveConfig().proxyConcurrency ?? DEFAULT_PROXY_CONCURRENCY;
  const upstreamSemaphore = new Semaphore(proxyConcurrency);
  const server = http.createServer(async (req, res) => {
    if (req.method !== "POST") {
      res.writeHead(405, { "Content-Type": "application/json", "Connection": "close" });
      res.end(JSON.stringify({ error: "Method not allowed" }));
      req.socket.destroy();
      return;
    }
    try {
      logDebug(`[GuardClaw Proxy] Incoming ${req.method} ${req.url}`);
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
        res.end(JSON.stringify({ error: { message: "Invalid JSON in request body", type: "invalid_request" } }));
        return;
      }
      const injectionCfg = getLiveInjectionConfig();
      if (injectionCfg.enabled !== false) {
        const proxyMessages = parsed.messages;
        logDebug(`[GuardClaw S0] messages=${proxyMessages ? proxyMessages.length : "undefined"} keys=${Object.keys(parsed).join(",")}`);
        const lastUserMsg = proxyMessages?.slice().reverse().find((m) => String(m.role ?? "") === "user");
        logDebug(`[GuardClaw S0] lastUserMsg role=${lastUserMsg?.role} contentType=${typeof lastUserMsg?.content}`);
        let userContent = "";
        if (lastUserMsg) {
          if (typeof lastUserMsg.content === "string") {
            userContent = lastUserMsg.content;
          } else if (Array.isArray(lastUserMsg.content)) {
            userContent = lastUserMsg.content.map((p) => {
              if (typeof p === "string") return p;
              if (p && typeof p === "object") {
                const block = p;
                if (typeof block.text === "string") return block.text;
                if (typeof block.content === "string") return block.content;
              }
              return "";
            }).join("");
          }
        }
        logDebug(`[GuardClaw S0] userContent length=${userContent.length} first80=${userContent.slice(0, 80).replace(/\n/g, "\\n")}`);
        let proxySenderId = req.headers["x-guardclaw-sender-id"];
        if (!proxySenderId && userContent) {
          const m = userContent.match(/"sender_id"\s*:\s*"(\d+)"/);
          if (m) proxySenderId = m[1];
        }
        if (proxySenderId && (injectionCfg.banned_senders ?? []).includes(proxySenderId)) {
          log.warn(`[GuardClaw S0] BANNED sender blocked in proxy: senderId=${proxySenderId}`);
          res.writeHead(403, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: { message: `GuardClaw S0: Sender ${proxySenderId} is banned`, type: "forbidden" } }));
          return;
        }
        const isExemptSender = proxySenderId && (injectionCfg.exempt_senders ?? []).includes(proxySenderId);
        if (userContent && !isExemptSender) {
          const proxyInjResult = await detectInjection(userContent, "user_message", injectionCfg);
          const proxySessionKey = req.headers["x-guardclaw-session"] ?? "proxy";
          logDebug(`[GuardClaw S0] detection result: action=${proxyInjResult.action} score=${proxyInjResult.score} matches=${proxyInjResult.matches.join(",")}`);
          if (proxyInjResult.action === "block") {
            log.warn(`[GuardClaw S0] BLOCKED in proxy session=${proxySessionKey} score=${proxyInjResult.score} patterns=${proxyInjResult.matches.join(",")}`);
            await appendProxyInjectionLog({
              ts: (/* @__PURE__ */ new Date()).toISOString(),
              session: proxySessionKey,
              senderId: proxySenderId,
              action: "block",
              score: proxyInjResult.score,
              patterns: proxyInjResult.matches,
              source: "proxy",
              preview: userContent.slice(0, 80)
            });
            if (proxySenderId) {
              const attempts = recordInjectionAttempt(proxySenderId);
              const alreadyBanned = (injectionCfg.banned_senders ?? []).includes(proxySenderId);
              if (attempts >= 2 && !alreadyBanned && !pendingBans.has(proxySenderId)) {
                pendingBans.add(proxySenderId);
                log.warn(`[GuardClaw S0] AUTO-BANNING senderId=${proxySenderId} after ${attempts} proxy injection attempts`);
                const newBanned = [...injectionCfg.banned_senders ?? [], proxySenderId];
                updateLiveInjectionConfig({ banned_senders: newBanned });
                withConfigWriteLock(async () => {
                  const raw = await fs3.promises.readFile(GUARDCLAW_JSON_PATH, "utf8");
                  const cfg = JSON.parse(raw);
                  if (!cfg.privacy) cfg.privacy = {};
                  const privacy = cfg.privacy;
                  if (!privacy.injection) privacy.injection = {};
                  privacy.injection.banned_senders = newBanned;
                  await fs3.promises.writeFile(GUARDCLAW_JSON_PATH, JSON.stringify(cfg, null, 2));
                }).catch((err) => {
                  log.warn(`[GuardClaw S0] Failed to persist ban for ${proxySenderId}: ${String(err)}`);
                }).finally(() => {
                  pendingBans.delete(proxySenderId);
                });
              }
            }
            res.writeHead(403, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: { message: `GuardClaw S0: ${proxyInjResult.blocked_reason ?? "Prompt injection detected"}`, type: "forbidden" } }));
            return;
          } else if (proxyInjResult.action === "sanitise" && proxyInjResult.sanitised !== userContent && lastUserMsg) {
            log.warn(`[GuardClaw S0] SANITISED in proxy session=${proxySessionKey}`);
            await appendProxyInjectionLog({
              ts: (/* @__PURE__ */ new Date()).toISOString(),
              session: proxySessionKey,
              senderId: proxySenderId,
              action: "sanitise",
              score: proxyInjResult.score,
              patterns: proxyInjResult.matches,
              source: "proxy",
              preview: userContent.slice(0, 80)
            });
            if (typeof lastUserMsg.content === "string") {
              lastUserMsg.content = proxyInjResult.sanitised;
            } else if (Array.isArray(lastUserMsg.content)) {
              for (const part of lastUserMsg.content) {
                if (typeof part.text === "string") {
                  part.text = proxyInjResult.sanitised;
                  break;
                }
              }
            }
          }
        }
      }
      const hadOpenAiMarkers = stripPiiMarkers(parsed.messages ?? []);
      const hadGoogleMarkers = stripPiiMarkersGoogleContents(parsed.contents);
      if (hadOpenAiMarkers || hadGoogleMarkers) {
        logDebug("[GuardClaw Proxy] Stripped S2 PII markers from request");
      }
      const hadOpenAiSchemaFix = cleanToolSchemas(parsed.tools);
      const hadGoogleSchemaFix = cleanGoogleToolSchemas(parsed.tools);
      if (hadOpenAiSchemaFix || hadGoogleSchemaFix) {
        logDebug("[GuardClaw Proxy] Cleaned unsupported keywords from tool schemas");
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
            logDebug("[GuardClaw Proxy] Defense-in-depth: rule-based PII redaction applied to message");
          }
        } else if (Array.isArray(msg.content)) {
          for (const part of msg.content) {
            if (part && typeof part.text === "string") {
              const redacted = redactSensitiveInfo(part.text, redactionOpts);
              if (redacted !== part.text) {
                part.text = redacted;
                logDebug("[GuardClaw Proxy] Defense-in-depth: rule-based PII redaction applied to message part");
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
                logDebug("[GuardClaw Proxy] Defense-in-depth: rule-based PII redaction applied to Google part");
              }
            }
          }
        }
      }
      const sessionKey2 = req.headers["x-guardclaw-session"];
      const requestModel = parsed.model;
      const target = resolveTarget(sessionKey2, requestModel);
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
      const circuitKey = target.baseUrl;
      if (isCircuitOpen(circuitKey)) {
        log.warn(`[GuardClaw Proxy] Circuit OPEN for ${circuitKey} \u2014 rejecting without upstream call`);
        res.writeHead(503, { "Content-Type": "application/json", "Connection": "close" });
        res.end(JSON.stringify({ error: { message: "Upstream circuit breaker open \u2014 retrying in 30s", type: "circuit_open" } }));
        req.socket.destroy();
        return;
      }
      const acquired = await upstreamSemaphore.acquire(SEMAPHORE_TIMEOUT_MS);
      if (!acquired) {
        log.warn(`[GuardClaw Proxy] Upstream concurrency limit reached (active=${upstreamSemaphore.active}, queued=${upstreamSemaphore.queued}) \u2014 rejecting`);
        res.writeHead(503, { "Content-Type": "application/json", "Connection": "close" });
        res.end(JSON.stringify({ error: { message: "Upstream concurrency limit exceeded", type: "concurrency_limit" } }));
        req.socket.destroy();
        return;
      }
      const upstreamHeaders = {
        "Content-Type": "application/json",
        ...resolveAuthHeaders(target)
      };
      const MAX_COMPLETION_TOKENS = 16384;
      for (const key of ["max_tokens", "max_completion_tokens"]) {
        if (parsed[key] != null && parsed[key] > MAX_COMPLETION_TOKENS) {
          logDebug(`[GuardClaw Proxy] Capped ${key} ${parsed[key]} \u2192 ${MAX_COMPLETION_TOKENS}`);
          parsed[key] = MAX_COMPLETION_TOKENS;
        }
      }
      const clientWantsStream = !!parsed.stream;
      const streamUpstream = clientWantsStream;
      logDebug(`[GuardClaw Proxy] \u2192 ${upstreamUrl} (stream=${clientWantsStream}, upstreamStream=${streamUpstream}, model=${requestModel ?? "unknown"}, provider=${target.provider})`);
      let upstreamOk = false;
      try {
        if (streamUpstream) {
          const streamOk = await tryStreamUpstream(parsed, upstreamUrl, upstreamHeaders, res, log);
          if (streamOk) {
            upstreamOk = true;
            recordUpstreamSuccess(circuitKey);
            return;
          }
          logDebug("[GuardClaw Proxy] Streaming unavailable, falling back to non-streaming + SSE conversion");
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
          const opened = recordUpstreamFailure(circuitKey);
          if (opened) log.warn(`[GuardClaw Proxy] Circuit OPENED for ${circuitKey} after ${CIRCUIT_FAILURE_THRESHOLD} consecutive failures`);
          const isTimeout = fetchErr instanceof Error && fetchErr.name === "AbortError";
          const clientMsg = isTimeout ? "Upstream request timed out (120s)" : "Upstream request failed";
          log.error(`[GuardClaw Proxy] Upstream fetch failed: ${String(fetchErr)}`);
          res.writeHead(504, { "Content-Type": "application/json", "Connection": "close" });
          res.end(JSON.stringify({ error: { message: clientMsg, type: "proxy_timeout" } }));
          req.socket.destroy();
          return;
        }
        clearTimeout(nonStreamTimeout);
        upstreamOk = true;
        recordUpstreamSuccess(circuitKey);
        const responseText = await upstream.text();
        logDebug(`[GuardClaw Proxy] Upstream responded: status=${upstream.status} ok=${upstream.ok} bodyLen=${responseText.length}`);
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
      } finally {
        upstreamSemaphore.release();
      }
    } catch (err) {
      log.error(`[GuardClaw Proxy] Request failed: ${String(err)}`);
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json", "Connection": "close" });
      }
      if (!res.writableEnded) {
        res.end(JSON.stringify({
          error: {
            message: `GuardClaw proxy error: ${String(err)}`,
            type: "proxy_error"
          }
        }));
      }
      req.socket.destroy();
    }
  });
  server.keepAliveTimeout = 5e3;
  server.headersTimeout = 1e4;
  server.requestTimeout = 135e3;
  server.maxRequestsPerSocket = 25;
  const MAX_SOCKET_AGE_MS = 18e4;
  const REAP_INTERVAL_MS = 3e4;
  const activeSockets = /* @__PURE__ */ new Map();
  server.on("connection", (socket) => {
    activeSockets.set(socket, Date.now());
    socket.once("close", () => activeSockets.delete(socket));
  });
  const reaperInterval = setInterval(() => {
    const now = Date.now();
    let reaped = 0;
    for (const [socket, createdAt] of activeSockets) {
      if (now - createdAt > MAX_SOCKET_AGE_MS) {
        socket.destroy();
        activeSockets.delete(socket);
        reaped++;
      }
    }
    if (reaped > 0) {
      log.warn(`[GuardClaw Proxy] Reaper destroyed ${reaped} stale connections (${activeSockets.size} remaining)`);
    }
  }, REAP_INTERVAL_MS);
  if (typeof reaperInterval === "object" && "unref" in reaperInterval) {
    reaperInterval.unref();
  }
  server.on("error", (err) => {
    log.error(`[GuardClaw Proxy] Server error: ${String(err)}`);
  });
  return new Promise((resolve3, reject) => {
    server.listen(port, "127.0.0.1", () => {
      resolve3({
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
import { resolve, normalize } from "path";
var ALLOWED_ROUTER_DIRS = [
  resolve(process.env.HOME ?? "/tmp", ".openclaw", "routers"),
  resolve(process.env.HOME ?? "/tmp", ".openclaw", "plugins")
];
function isAllowedModulePath(modulePath) {
  const resolved = resolve(normalize(modulePath));
  return ALLOWED_ROUTER_DIRS.some((dir) => resolved.startsWith(dir + "/") || resolved === dir);
}
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
    if (!isAllowedModulePath(modulePath)) {
      this.logger.error(`[RouterPipeline] Blocked load of custom router "${id}": path "${modulePath}" is outside allowed directories (${ALLOWED_ROUTER_DIRS.join(", ")})`);
      return;
    }
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

// src/secret-manager.ts
import { execFile } from "child_process";
import { promisify } from "util";
var execFileAsync = promisify(execFile);
var MAX_SECRET_BYTES = 8192;
var MAX_TRACKED_PER_SESSION = 50;
var MIN_SECRET_LENGTH = 4;
var trackedSecrets = /* @__PURE__ */ new Map();
var pendingKeychainFetch = /* @__PURE__ */ new Set();
async function readKeychainSecret(service, account) {
  if (!isValidLabel(service) || !isValidLabel(account)) {
    return { error: "Invalid service or account \u2014 only printable ASCII (1\u2013255 chars) allowed" };
  }
  try {
    const { stdout } = await execFileAsync(
      "security",
      ["find-generic-password", "-s", service, "-a", account, "-w"],
      { timeout: 5e3, maxBuffer: MAX_SECRET_BYTES }
    );
    return { value: stdout.trim() };
  } catch (err) {
    const e = err;
    return { error: e.stderr?.trim() || e.message || String(err) };
  }
}
function isValidLabel(s) {
  return typeof s === "string" && s.length > 0 && s.length <= 255 && /^[\x20-\x7E]+$/.test(s);
}
function trackSecret(sessionKey2, value) {
  if (!value || value.length < MIN_SECRET_LENGTH) return;
  let set = trackedSecrets.get(sessionKey2);
  if (!set) {
    set = /* @__PURE__ */ new Set();
    trackedSecrets.set(sessionKey2, set);
  }
  if (set.size < MAX_TRACKED_PER_SESSION) {
    set.add(value);
  }
}
function markKeychainFetchPending(sessionKey2) {
  pendingKeychainFetch.add(sessionKey2);
}
function consumeKeychainFetchPending(sessionKey2) {
  const had = pendingKeychainFetch.has(sessionKey2);
  pendingKeychainFetch.delete(sessionKey2);
  return had;
}
function containsTrackedSecret(sessionKey2, text) {
  const set = trackedSecrets.get(sessionKey2);
  if (!set) return false;
  for (const secret of set) {
    if (text.includes(secret)) return true;
  }
  return false;
}
function redactTrackedSecrets(sessionKey2, text) {
  const set = trackedSecrets.get(sessionKey2);
  if (!set || set.size === 0) return text;
  let result = text;
  for (const secret of set) {
    result = result.split(secret).join("[REDACTED:SECRET]");
  }
  return result;
}
function clearSessionSecrets(sessionKey2) {
  trackedSecrets.delete(sessionKey2);
  pendingKeychainFetch.delete(sessionKey2);
}
var NETWORK_TOOL_EXACT = /* @__PURE__ */ new Set([
  "web_fetch",
  "web_search",
  "http_get",
  "http_post",
  "http_request",
  "fetch",
  "curl",
  "wget",
  "browse",
  "browser",
  "websearch",
  "search_web",
  "url_fetch",
  "http",
  "get_url",
  "post_url"
]);
function isNetworkTool(toolName) {
  const lower = toolName.toLowerCase();
  if (NETWORK_TOOL_EXACT.has(lower)) return true;
  if (lower.startsWith("mcp__") && (lower.includes("fetch") || lower.includes("http") || lower.includes("search") || lower.includes("browse") || lower.includes("curl"))) return true;
  return false;
}
function parseKeychainCommand(command) {
  if (!command.includes("security") || !command.includes("find-generic-password")) return null;
  const m1 = command.match(
    /\bsecurity\s+find-generic-password\b[^|]*?-s\s+["']([^"']+)["'][^|]*?-a\s+["']([^"']+)["'][^|]*?-w\b/
  ) || command.match(
    /\bsecurity\s+find-generic-password\b[^|]*?-s\s+(\S+)[^|]*?-a\s+(\S+)[^|]*?-w\b/
  );
  if (m1) return { service: m1[1], account: m1[2] };
  const m2 = command.match(
    /\bsecurity\s+find-generic-password\b[^|]*?-a\s+["']([^"']+)["'][^|]*?-s\s+["']([^"']+)["'][^|]*?-w\b/
  ) || command.match(
    /\bsecurity\s+find-generic-password\b[^|]*?-a\s+(\S+)[^|]*?-s\s+(\S+)[^|]*?-w\b/
  );
  if (m2) return { service: m2[2], account: m2[1] };
  return null;
}

// src/response-scanner.ts
var SECRET_PATTERNS = [
  // PEM private keys
  {
    name: "private_key",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/i
  },
  // OpenAI — classic sk-... and newer sk-proj-... format
  {
    name: "openai_key",
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b/
  },
  // Anthropic
  {
    name: "anthropic_key",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/
  },
  // AWS access key ID
  {
    name: "aws_access_key",
    pattern: /\b(?:AKIA|ASIA|AROA|ANPA|ANVA|AIDA)[0-9A-Z]{16}\b/
  },
  // GitHub tokens (fine-grained and classic)
  {
    name: "github_token",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/
  },
  // Google service account / API key format (AIza...)
  {
    name: "google_key",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/
  },
  // Bearer token in HTTP header context
  {
    name: "bearer_token",
    pattern: /Authorization:\s*Bearer\s+[A-Za-z0-9._\-]{20,}/i
  },
  // Database connection strings with embedded credentials
  {
    name: "db_connection_string",
    pattern: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^:@\s]{1,64}:[^@\s]{6,}@/i
  },
  // .env style key=value with a long value (high-entropy credentials)
  {
    name: "env_credential",
    pattern: /(?:API_KEY|SECRET(?:_KEY)?|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|APP_SECRET)\s*=\s*["']?[A-Za-z0-9+\/=_\-]{20,}["']?/i
  }
];
var PII_PATTERNS = [
  // US Social Security Number
  { name: "us_ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
  // 16-digit credit card with spaces/dashes
  { name: "credit_card", pattern: /\b(?:\d{4}[- ]){3}\d{4}\b/ }
];
function redactMatches(text, found) {
  let result = text;
  for (const { name, match } of found) {
    result = result.split(match).join(`[REDACTED:${name.toUpperCase()}]`);
  }
  return result;
}
function scanResponse(text, config) {
  const action = config.action ?? "warn";
  const scanSecrets = config.scanSecrets !== false;
  const scanPii = config.scanPii === true;
  const found = [];
  if (scanSecrets) {
    for (const { name, pattern } of SECRET_PATTERNS) {
      const m = text.match(pattern);
      if (m) found.push({ name, match: m[0] });
    }
  }
  if (scanPii) {
    for (const { name, pattern } of PII_PATTERNS) {
      const m = text.match(pattern);
      if (m) found.push({ name, match: m[0] });
    }
  }
  if (found.length === 0) {
    return { hit: false, matches: [], action };
  }
  const matchNames = [...new Set(found.map((f) => f.name))];
  const reason = `response contained: ${matchNames.join(", ")}`;
  let redacted;
  if (action === "redact") {
    redacted = redactMatches(text, found);
  }
  return { hit: true, matches: matchNames, reason, redacted, action };
}

// src/budget-guard.ts
import { readFile, writeFile, rename } from "fs/promises";
import { join as join5 } from "path";
var HOME = process.env.HOME ?? process.env.USERPROFILE ?? "/tmp";
var BUDGET_PATH = join5(HOME, ".openclaw", "guardclaw-budget.json");
var _data = { dailyCosts: {}, monthlyCosts: {}, lastUpdated: "" };
async function loadBudgetData() {
  try {
    const raw = await readFile(BUDGET_PATH, "utf-8");
    _data = JSON.parse(raw);
    const cutoff = /* @__PURE__ */ new Date();
    cutoff.setUTCDate(cutoff.getUTCDate() - 35);
    for (const key of Object.keys(_data.dailyCosts)) {
      if (new Date(key) < cutoff) delete _data.dailyCosts[key];
    }
    const monthCutoff = /* @__PURE__ */ new Date();
    monthCutoff.setUTCMonth(monthCutoff.getUTCMonth() - 13);
    for (const key of Object.keys(_data.monthlyCosts)) {
      const [y, m] = key.split("-").map(Number);
      if (new Date(Date.UTC(y, m - 1)) < monthCutoff) delete _data.monthlyCosts[key];
    }
  } catch {
  }
}
async function persistBudget() {
  _data.lastUpdated = (/* @__PURE__ */ new Date()).toISOString();
  const tmp = BUDGET_PATH + ".tmp";
  try {
    await writeFile(tmp, JSON.stringify(_data, null, 2), { encoding: "utf-8", mode: 384 });
    await rename(tmp, BUDGET_PATH);
  } catch {
  }
}
function calculateCost(model, usage, pricing) {
  const input = usage.input ?? 0;
  const output = usage.output ?? 0;
  if (input === 0 && output === 0) return 0;
  const modelLower = model.toLowerCase();
  let p;
  p = pricing[model] ?? pricing[modelLower];
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
  return (input * inputRate + output * outputRate) / 1e6;
}
function todayKey() {
  return (/* @__PURE__ */ new Date()).toISOString().slice(0, 10);
}
function thisMonthKey() {
  return (/* @__PURE__ */ new Date()).toISOString().slice(0, 7);
}
function recordCost(cost) {
  if (cost <= 0) return;
  const day = todayKey();
  const month = thisMonthKey();
  _data.dailyCosts[day] = (_data.dailyCosts[day] ?? 0) + cost;
  _data.monthlyCosts[month] = (_data.monthlyCosts[month] ?? 0) + cost;
  persistBudget().catch(() => {
  });
}
function getDailyCost(date = todayKey()) {
  return _data.dailyCosts[date] ?? 0;
}
function getMonthlyCost(month = thisMonthKey()) {
  return _data.monthlyCosts[month] ?? 0;
}
function checkBudget(config) {
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
    action
  };
}
function getBudgetSnapshot() {
  return _data;
}

// src/behavioral-log.ts
import { appendFile, readFile as readFile2, writeFile as writeFile2, rename as rename2 } from "fs/promises";
import { join as join6 } from "path";
var HOME2 = process.env.HOME ?? process.env.USERPROFILE ?? "/tmp";
var LOG_PATH = join6(HOME2, ".openclaw", "guardclaw-behavior.jsonl");
var _seqCounters = /* @__PURE__ */ new Map();
var _pendingEvents = /* @__PURE__ */ new Map();
function fnv32a(str) {
  let hash = 2166136261;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = hash * 16777619 >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}
function categoriseTool(toolName) {
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
function agentFromSession(sessionKey2) {
  const parts = sessionKey2.split(":");
  if (parts[0] === "agent" && parts.length >= 2) return parts[1];
  return parts[0] ?? "unknown";
}
function logToolEvent(sessionKey2, toolName, params2, sensitivity) {
  try {
    const seq = (_seqCounters.get(sessionKey2) ?? 0) + 1;
    _seqCounters.set(sessionKey2, seq);
    const event = {
      ts: (/* @__PURE__ */ new Date()).toISOString(),
      session: sessionKey2,
      agent: agentFromSession(sessionKey2),
      seq,
      tool: toolName,
      category: categoriseTool(toolName),
      sensitivity,
      paramsHash: fnv32a(JSON.stringify(params2)),
      secretOpMs: null
    };
    const pending = _pendingEvents.get(sessionKey2) ?? [];
    pending.push(event);
    _pendingEvents.set(sessionKey2, pending);
    appendFile(LOG_PATH, JSON.stringify(event) + "\n", { encoding: "utf-8", mode: 384 }).catch(() => {
    });
  } catch {
  }
}
function clearBehavioralSession(sessionKey2) {
  _seqCounters.delete(sessionKey2);
  _pendingEvents.delete(sessionKey2);
}
function getRecentEvents(sessionKey2, limit = 10) {
  const pending = _pendingEvents.get(sessionKey2) ?? [];
  return pending.slice(-limit);
}

// src/secret-ops.ts
import { readFile as readFile3 } from "fs/promises";
import { join as join7 } from "path";
import { execFile as execFile2 } from "child_process";
import { promisify as promisify2 } from "util";

// src/behavioral-attestation.ts
function score(events) {
  if (events.length === 0) return { score: 0, signals: ["no prior tool calls \u2014 no behavioral context"] };
  let s = 0;
  const signals = [];
  const categories = events.map((e) => e.category);
  const uniqueCategories = new Set(categories);
  const fileReads = events.filter((e) => e.category === "file_read").length;
  const webFetches = events.filter((e) => e.category === "web_fetch").length;
  const s3Events = events.filter((e) => e.sensitivity === "S3").length;
  const lastCategory = categories[categories.length - 1];
  if (fileReads >= 4) {
    s += 0.35;
    signals.push(`${fileReads} file reads in last ${events.length} calls (bulk read pattern)`);
  } else if (fileReads >= 2) {
    s += 0.1;
    signals.push(`${fileReads} file reads in last ${events.length} calls`);
  }
  if (webFetches >= 3) {
    s += 0.25;
    signals.push(`${webFetches} web fetches in last ${events.length} calls`);
  } else if (webFetches >= 2) {
    s += 0.1;
    signals.push(`${webFetches} web fetches in last ${events.length} calls`);
  }
  if (lastCategory === "shell") {
    s += 0.2;
    signals.push("shell call immediately before secret operation");
  }
  if (s3Events >= 2) {
    s += 0.15;
    signals.push(`${s3Events} S3-sensitivity events in window`);
  } else if (s3Events === 1) {
    s += 0.05;
    signals.push("1 S3-sensitivity event in window");
  }
  if (uniqueCategories.size >= 5) {
    s += 0.1;
    signals.push(`${uniqueCategories.size} different tool categories (erratic pattern)`);
  }
  if (uniqueCategories.size === 1) {
    s -= 0.2;
    signals.push(`consistent task \u2014 all ${events.length} calls are ${categories[0]}`);
  }
  if (events.length === 1) {
    s -= 0.1;
    signals.push("minimal context \u2014 only 1 prior tool call");
  }
  return {
    score: Math.max(0, Math.min(1, s)),
    signals
  };
}

// src/secret-ops.ts
var execFileAsync2 = promisify2(execFile2);
var HOME3 = process.env.HOME ?? process.env.USERPROFILE ?? "/tmp";
var SECRETS_REGISTRY_PATH = join7(HOME3, ".openclaw", "guardclaw-secrets.json");
var AUTO_DENY_SCORE = 0.75;
var INTENT_VERIFY_TIMEOUT_MS = 3e3;
var MAX_HTTP_RESPONSE_BYTES = 32768;
var INJECT_EXEC_TIMEOUT_MS = 3e4;
var _registryCache = null;
var _registryCacheTs = 0;
var REGISTRY_CACHE_TTL_MS = 3e4;
async function loadSecretRegistry() {
  const now = Date.now();
  if (_registryCache && now - _registryCacheTs < REGISTRY_CACHE_TTL_MS) {
    return _registryCache;
  }
  try {
    const raw = await readFile3(SECRETS_REGISTRY_PATH, "utf-8");
    _registryCache = JSON.parse(raw);
    _registryCacheTs = now;
    return _registryCache;
  } catch {
    _registryCache = { secrets: {} };
    _registryCacheTs = now;
    return _registryCache;
  }
}
async function resolveSecret(entry) {
  const { source } = entry;
  if (source.type === "keychain") {
    return readKeychainSecret(source.service, source.account);
  }
  if (source.type === "config") {
    try {
      const filePath = source.file.replace(/^~/, HOME3);
      const raw = await readFile3(filePath, "utf-8");
      const obj = JSON.parse(raw);
      const parts = source.jsonPath.split(".");
      let cursor = obj;
      for (const part of parts) {
        if (cursor == null || typeof cursor !== "object") {
          return { error: `Path "${source.jsonPath}" not found in ${filePath}` };
        }
        cursor = cursor[part];
      }
      if (typeof cursor !== "string" || !cursor) {
        return { error: `Path "${source.jsonPath}" is not a non-empty string in ${filePath}` };
      }
      return { value: cursor };
    } catch (err) {
      return { error: String(err) };
    }
  }
  return { error: "Unknown secret source type" };
}
async function verifyIntent(secretName, entry, operation, opParams, sessionKey2, privacyConfig) {
  const localModelCfg = privacyConfig.localModel;
  if (!localModelCfg?.enabled || !localModelCfg.endpoint || !localModelCfg.model) {
    return { decision: "DENY", reason: "No local model configured for intent verification" };
  }
  const recentEvents = getRecentEvents(sessionKey2, 10);
  const eventSummary = recentEvents.length === 0 ? "(no prior tool calls in this session)" : recentEvents.map(
    (e, i) => `${i + 1}. [${e.category}] ${e.tool}${e.sensitivity ? ` (${e.sensitivity})` : ""}`
  ).join("\n");
  const safeParams = sanitizeParamsForVerifier(opParams);
  const messages = [
    {
      role: "system",
      content: "You are a security intent verifier. An AI agent has requested access to a secret credential. Determine if this request appears legitimate given the recent tool call history. Reply with exactly: ALLOW or DENY on the first line, then a brief reason on the second line. Be conservative \u2014 deny if anything looks suspicious or out of context."
    },
    {
      role: "user",
      content: `Secret name: ${secretName}
Description: ${entry.description}
Operation: ${operation}
Parameters: ${JSON.stringify(safeParams)}

Recent tool call history (last ${recentEvents.length} calls):
${eventSummary}

Is this secret access request legitimate? Reply ALLOW or DENY, then brief reason.`
    }
  ];
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), INTENT_VERIFY_TIMEOUT_MS);
    let text = "";
    try {
      const result = await Promise.race([
        callChatCompletion(localModelCfg.endpoint, localModelCfg.model, messages, {
          temperature: 0,
          maxTokens: 80,
          providerType: localModelCfg.type ?? "openai-compatible",
          apiKey: localModelCfg.apiKey
        }),
        new Promise(
          (_, reject) => setTimeout(() => reject(new Error("intent-verify-timeout")), INTENT_VERIFY_TIMEOUT_MS)
        )
      ]);
      text = result.text.trim();
    } finally {
      clearTimeout(timeout);
    }
    const firstLine = text.split("\n")[0]?.trim().toUpperCase() ?? "";
    const reasonLine = text.split("\n").slice(1).join(" ").trim();
    const decision = firstLine.startsWith("ALLOW") ? "ALLOW" : "DENY";
    return { decision, reason: reasonLine || (decision === "ALLOW" ? "Looks legitimate" : "Suspicious pattern") };
  } catch (err) {
    const msg = String(err);
    if (msg.includes("intent-verify-timeout")) {
      return { decision: "DENY", reason: "Intent verifier timed out \u2014 failing closed for safety" };
    }
    return { decision: "DENY", reason: `Intent verifier error: ${msg}` };
  }
}
function sanitizeParamsForVerifier(params2) {
  const out = {};
  for (const [k, v] of Object.entries(params2)) {
    if (typeof v === "string" && (v.length > 40 || /key|token|secret|password|bearer/i.test(k))) {
      out[k] = `[${v.length} chars]`;
    } else {
      out[k] = v;
    }
  }
  return out;
}
async function opDescribe(entry) {
  return `Secret: ${entry.description}
Allowed operations: ${(entry.allowedOps ?? ["describe"]).join(", ")}`;
}
async function opMakeHttpRequest(secretValue, entry, params2) {
  const url = String(params2.url ?? "");
  if (!url || !/^https?:\/\//.test(url)) {
    throw new Error("make_http_request requires a valid http(s) url in params.url");
  }
  const method = String(params2.method ?? "GET").toUpperCase();
  const headerName = entry.httpHeader ?? "Authorization";
  const headerValue = headerName === "Authorization" ? `Bearer ${secretValue}` : secretValue;
  const headers = {
    [headerName]: headerValue,
    "Content-Type": "application/json",
    ...params2.headers ?? {}
  };
  headers[headerName] = headerValue;
  const body = params2.body != null ? typeof params2.body === "string" ? params2.body : JSON.stringify(params2.body) : void 0;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15e3);
  try {
    const resp = await fetch(url, {
      method,
      headers,
      body: method !== "GET" && method !== "HEAD" ? body : void 0,
      signal: controller.signal
    });
    let responseText = await resp.text();
    if (responseText.length > MAX_HTTP_RESPONSE_BYTES) {
      responseText = responseText.slice(0, MAX_HTTP_RESPONSE_BYTES) + "\n[truncated]";
    }
    return `HTTP ${resp.status} ${resp.statusText}
${responseText}`;
  } finally {
    clearTimeout(timeout);
  }
}
async function opInjectEnvVars(secretValue, entry, params2) {
  const command = String(params2.command ?? "");
  if (!command) {
    throw new Error("inject_env_vars requires params.command \u2014 the shell command to run with the secret injected");
  }
  const envVarName = entry.envVarName;
  if (!envVarName) {
    throw new Error(`Secret entry does not have an envVarName configured \u2014 cannot inject env var`);
  }
  const env = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v != null) env[k] = v;
  }
  env[envVarName] = secretValue;
  const extraEnv = params2.env ?? {};
  for (const [k, v] of Object.entries(extraEnv)) {
    if (typeof v === "string" && !k.toLowerCase().includes("secret") && !k.toLowerCase().includes("token") && !k.toLowerCase().includes("key") && !k.toLowerCase().includes("password")) {
      env[k] = v;
    }
  }
  try {
    const { stdout, stderr } = await execFileAsync2(
      "sh",
      ["-c", command],
      { env, timeout: INJECT_EXEC_TIMEOUT_MS, maxBuffer: MAX_HTTP_RESPONSE_BYTES }
    );
    const out = stdout.trim();
    const err = stderr.trim();
    const parts = [];
    if (out) parts.push(out);
    if (err) parts.push(`[stderr] ${err}`);
    return parts.join("\n") || "(command produced no output)";
  } catch (execErr) {
    const e = execErr;
    const msg = e.stderr?.trim() || e.message || String(execErr);
    throw new Error(`Command failed (exit ${e.code ?? "?"}): ${msg}`);
  }
}
async function handleUseSecret(rawParams, sessionKey2, privacyConfig, webhooks, logger) {
  const name = String(rawParams.name ?? "").trim();
  const operation = String(rawParams.operation ?? "describe");
  const opParams = rawParams.params ?? {};
  const registry = await loadSecretRegistry();
  const entry = registry.secrets[name];
  if (!entry) {
    return {
      ok: false,
      reason: `Unknown secret "${name}". Available secrets: ${Object.keys(registry.secrets).join(", ") || "(none registered)"}`
    };
  }
  const allowedOps = entry.allowedOps ?? ["describe"];
  if (!allowedOps.includes(operation)) {
    return {
      ok: false,
      reason: `Operation "${operation}" is not permitted for secret "${name}". Allowed: ${allowedOps.join(", ")}`
    };
  }
  const baConfig = privacyConfig.behavioralAttestation;
  const windowSize = baConfig?.windowSize ?? 10;
  const recentEvents = getRecentEvents(sessionKey2, windowSize);
  const { score: suspicionScore, signals } = score(recentEvents);
  logger.info(
    `[GuardClaw:secrets] use_secret "${name}":${operation} \u2014 behavioral score=${suspicionScore.toFixed(2)} signals=[${signals.join("; ")}]`
  );
  if (suspicionScore >= AUTO_DENY_SCORE) {
    const reason = `Behavioral attestation auto-denied: score=${suspicionScore.toFixed(2)} (${signals.join("; ")})`;
    logger.warn(`[GuardClaw:secrets] DENIED ${name}:${operation} \u2014 ${reason}`);
    _notify("secret_denied", { name, operation, sessionKey: sessionKey2, reason, score: suspicionScore }, webhooks);
    return { ok: false, reason, notify: true };
  }
  if (operation !== "describe") {
    const { decision, reason: verifierReason } = await verifyIntent(
      name,
      entry,
      operation,
      opParams,
      sessionKey2,
      privacyConfig
    );
    if (decision === "DENY") {
      const reason = `Intent verifier denied: ${verifierReason}`;
      logger.warn(`[GuardClaw:secrets] DENIED ${name}:${operation} \u2014 ${reason}`);
      _notify("secret_denied", { name, operation, sessionKey: sessionKey2, reason, score: suspicionScore }, webhooks);
      return { ok: false, reason, notify: true };
    }
    logger.info(`[GuardClaw:secrets] ALLOWED ${name}:${operation} \u2014 ${verifierReason}`);
    _notify("secret_allowed", { name, operation, sessionKey: sessionKey2, reason: verifierReason, score: suspicionScore }, webhooks);
  }
  try {
    if (operation === "describe") {
      const result = await opDescribe(entry);
      return { ok: true, result };
    }
    const resolved = await resolveSecret(entry);
    if ("error" in resolved) {
      return { ok: false, reason: `Could not resolve secret "${name}": ${resolved.error}` };
    }
    if (operation === "make_http_request") {
      const result = await opMakeHttpRequest(resolved.value, entry, opParams);
      return { ok: true, result };
    }
    if (operation === "inject_env_vars") {
      const result = await opInjectEnvVars(resolved.value, entry, opParams);
      return { ok: true, result };
    }
    return { ok: false, reason: `Unimplemented operation: ${operation}` };
  } catch (err) {
    return { ok: false, reason: `Operation "${operation}" failed: ${String(err)}` };
  }
}
function _notify(event, details, webhooks) {
  if (!webhooks || webhooks.length === 0) return;
  import("./webhook-4O4RMVPQ.js").then(({ fireWebhooks: fireWebhooks2 }) => {
    fireWebhooks2(event, { sessionKey: String(details.sessionKey ?? ""), reason: String(details.reason ?? ""), details }, webhooks);
  }).catch(() => {
  });
}

// src/taint-store.ts
var MIN_TAINT_LENGTH = 4;
var MAX_TAINTS_PER_SESSION = 200;
var EVICTION_BATCH_FRACTION = 0.25;
var _taints = /* @__PURE__ */ new Map();
var _sources = /* @__PURE__ */ new Map();
var _pending = /* @__PURE__ */ new Map();
function registerTaint(sessionKey2, value, source, sensitivity, minLength = MIN_TAINT_LENGTH) {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length < minLength) return;
  let set = _taints.get(sessionKey2);
  if (!set) {
    set = /* @__PURE__ */ new Set();
    _taints.set(sessionKey2, set);
  }
  if (set.has(trimmed)) return;
  if (set.size >= MAX_TAINTS_PER_SESSION) {
    const srcMap2 = _sources.get(sessionKey2);
    const batchTarget = Math.max(1, Math.floor(MAX_TAINTS_PER_SESSION * EVICTION_BATCH_FRACTION));
    let evictedCount = 0;
    if (srcMap2) {
      const candidates = [];
      for (const [candidate, label] of srcMap2) {
        if (!label.includes(":secrets-file:")) {
          candidates.push(candidate);
          if (candidates.length >= batchTarget) break;
        }
      }
      for (const candidate of candidates) {
        set.delete(candidate);
        srcMap2.delete(candidate);
        evictedCount++;
      }
    }
    if (evictedCount > 0) {
      console.warn(
        `[GuardClaw:taint] Cap hit (session=${sessionKey2}): batch-evicted ${evictedCount} oldest evictable taints (cap=${MAX_TAINTS_PER_SESSION}, remaining=${set.size})`
      );
    } else {
      console.warn(
        `[GuardClaw:taint] Cap hit (session=${sessionKey2}): all ${MAX_TAINTS_PER_SESSION} slots are secrets-mount protected \u2014 dropping new entry from source="${source}"`
      );
      return;
    }
  }
  set.add(trimmed);
  let srcMap = _sources.get(sessionKey2);
  if (!srcMap) {
    srcMap = /* @__PURE__ */ new Map();
    _sources.set(sessionKey2, srcMap);
  }
  srcMap.set(trimmed, `${sensitivity}:${source}`);
}
function markPendingTaint(sessionKey2, source, sensitivity) {
  const queue = _pending.get(sessionKey2) ?? [];
  queue.push({ source, sensitivity });
  _pending.set(sessionKey2, queue);
}
function consumePendingTaint(sessionKey2) {
  const queue = _pending.get(sessionKey2);
  if (!queue || queue.length === 0) return null;
  const entry = queue.shift();
  if (queue.length === 0) _pending.delete(sessionKey2);
  return entry;
}
function extractTaintValues(content, minLength = MIN_TAINT_LENGTH) {
  const collected = /* @__PURE__ */ new Set();
  const trimmedFull = content.trim();
  if (!trimmedFull) return [];
  if (!trimmedFull.includes("\n")) {
    if (trimmedFull.length >= minLength && trimmedFull.length <= 8192) {
      collected.add(trimmedFull);
    }
    return [...collected];
  }
  for (const rawLine of trimmedFull.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("//")) continue;
    const envMatch = line.match(/^(?:export\s+)?[A-Z_][A-Z0-9_]*\s*=\s*(.+)$/i);
    if (envMatch) {
      const val = envMatch[1].trim().replace(/^["']|["']$/g, "");
      if (val.length >= minLength) collected.add(val);
      continue;
    }
    if (line.length >= minLength && line.length <= 8192) {
      collected.add(line);
    }
  }
  if (trimmedFull.length >= minLength && trimmedFull.length <= 8192) {
    collected.add(trimmedFull);
  }
  return [...collected];
}
function isSecretsMountPath(filePath) {
  const normalized = filePath.replace(/\\/g, "/");
  return normalized.startsWith("/run/secrets/") || normalized.startsWith("/var/run/secrets/");
}

// src/hooks.ts
function getPipelineConfig() {
  return { privacy: getLiveConfig() };
}
var _lastPrimaryWasCloud = null;
function isPrimaryModelCloud(api) {
  const defaults = api.config.agents?.defaults;
  const primaryModel = defaults?.model?.primary ?? "";
  const provider = primaryModel.includes("/") ? primaryModel.split("/")[0] : "";
  if (!provider) return true;
  const liveConfig = getLiveConfig();
  const isCloud = !isLocalProvider(provider, liveConfig.localProviders);
  if (isCloud && _lastPrimaryWasCloud === false) {
    api.logger.info("[GuardClaw] Primary model switched local \u2192 cloud \u2014 scrubbing MEMORY.md");
    const memMgr = getDefaultMemoryManager();
    memMgr.readMemory(true).then(async (content) => {
      if (!content.trim()) return;
      const scrubbed = redactSensitiveInfo(content, liveConfig.redaction);
      if (scrubbed !== content) {
        await memMgr.writeMemory(scrubbed, true);
        api.logger.info(`[GuardClaw] MEMORY.md scrubbed on cloud transition (${content.length} \u2192 ${scrubbed.length} chars)`);
      }
    }).catch((err) => {
      api.logger.error(`[GuardClaw] Failed to scrub MEMORY.md on cloud transition: ${String(err)}`);
    });
  }
  _lastPrimaryWasCloud = isCloud;
  return isCloud;
}
function gcDebug(logger, msg) {
  if (getLiveConfig().debugLogging) logger.info(msg);
}
function shouldUseFullMemoryTrack(sessionKey2) {
  if (isActiveLocalRouting(sessionKey2)) return true;
  if (isVerifiedGuardSession(sessionKey2)) return true;
  if (isSessionMarkedPrivate(sessionKey2)) {
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
var _synthesisPendingQueue = /* @__PURE__ */ new Map();
function _popSynthesisPending(sessionKey2, toolName) {
  const queue = _synthesisPendingQueue.get(sessionKey2);
  if (!queue || queue.length === 0) return void 0;
  const idx = queue.findIndex((e) => e.toolName === toolName);
  if (idx === -1) return void 0;
  const [entry] = queue.splice(idx, 1);
  if (queue.length === 0) _synthesisPendingQueue.delete(sessionKey2);
  return entry.synthetic;
}
var _OPENCLAW_DIR2 = join8(process.env.HOME ?? "/tmp", ".openclaw");
var GUARDCLAW_STATS_PATH = join8(_OPENCLAW_DIR2, "guardclaw-stats.json");
var GUARDCLAW_INJECTIONS_PATH2 = join8(_OPENCLAW_DIR2, "guardclaw-injections.json");
var GUARDCLAW_PENDING_CONFIG_PATH = join8(_OPENCLAW_DIR2, "workspace", "dashboard", "guardclaw-pending-config.json");
var GUARDCLAW_JSON_PATH2 = join8(_OPENCLAW_DIR2, "guardclaw.json");
var _pendingMemoryWrites = /* @__PURE__ */ new Map();
function trackMemoryWrite(sessionKey2, p) {
  let set = _pendingMemoryWrites.get(sessionKey2);
  if (!set) {
    set = /* @__PURE__ */ new Set();
    _pendingMemoryWrites.set(sessionKey2, set);
  }
  set.add(p);
  p.finally(() => {
    set?.delete(p);
  }).catch(() => {
  });
}
async function awaitPendingMemoryWrites(sessionKey2, logger) {
  const set = _pendingMemoryWrites.get(sessionKey2);
  if (!set || set.size === 0) return;
  logger.warn(`[GuardClaw] Awaiting ${set.size} pending memory write(s) before session lifecycle event (session=${sessionKey2})`);
  await Promise.allSettled([...set]);
  _pendingMemoryWrites.delete(sessionKey2);
}
async function appendInjectionLog(entry) {
  let entries = [];
  try {
    const raw = await fs4.promises.readFile(GUARDCLAW_INJECTIONS_PATH2, "utf8");
    try {
      const parsed = JSON.parse(raw);
      entries = Array.isArray(parsed) ? parsed : [];
    } catch {
    }
  } catch {
  }
  entries.push(entry);
  if (entries.length > 200) entries = entries.slice(entries.length - 200);
  try {
    await fs4.promises.writeFile(GUARDCLAW_INJECTIONS_PATH2, JSON.stringify(entries, null, 2), { mode: 384 });
  } catch (err) {
    console.warn(`[GuardClaw S0] Failed to write injection log: ${String(err)}`);
  }
}
async function writeStatsAtomic(stats) {
  const tmp = GUARDCLAW_STATS_PATH + ".tmp";
  await fs4.promises.writeFile(tmp, JSON.stringify(stats, null, 2), { mode: 384 });
  await fs4.promises.rename(tmp, GUARDCLAW_STATS_PATH);
}
async function updateS0Stats(action) {
  try {
    let stats = { s1Count: 0, s2Count: 0, s3Count: 0, totalMessages: 0, s3Policy: "local-only", lastUpdated: null };
    try {
      const raw = await fs4.promises.readFile(GUARDCLAW_STATS_PATH, "utf8");
      Object.assign(stats, JSON.parse(raw));
    } catch {
    }
    if (!stats.s0 || typeof stats.s0 !== "object") stats.s0 = { blocked: 0, sanitised: 0, total: 0 };
    const s0 = stats.s0;
    if (action === "block") s0.blocked = (s0.blocked ?? 0) + 1;
    else s0.sanitised = (s0.sanitised ?? 0) + 1;
    s0.total = (s0.total ?? 0) + 1;
    await writeStatsAtomic(stats);
  } catch {
  }
}
async function updateSynthesisStats(source, latencyMs, ok) {
  try {
    let stats = {};
    try {
      const raw = await fs4.promises.readFile(GUARDCLAW_STATS_PATH, "utf8");
      Object.assign(stats, JSON.parse(raw));
    } catch {
    }
    if (!stats.synthesis || typeof stats.synthesis !== "object") stats.synthesis = {};
    const syn = stats.synthesis;
    if (!syn[source] || typeof syn[source] !== "object") {
      syn[source] = { count: 0, failCount: 0, totalMs: 0, minMs: null, maxMs: null, lastMs: null, recentSamples: [] };
    }
    const bucket = syn[source];
    if (!ok) {
      bucket.failCount = (bucket.failCount ?? 0) + 1;
    } else {
      bucket.count = (bucket.count ?? 0) + 1;
      bucket.totalMs = (bucket.totalMs ?? 0) + latencyMs;
      bucket.minMs = bucket.minMs == null ? latencyMs : Math.min(bucket.minMs, latencyMs);
      bucket.maxMs = bucket.maxMs == null ? latencyMs : Math.max(bucket.maxMs, latencyMs);
      bucket.lastMs = latencyMs;
      const samples = bucket.recentSamples ?? [];
      samples.push(latencyMs);
      if (samples.length > 50) samples.shift();
      bucket.recentSamples = samples;
    }
    await writeStatsAtomic(stats);
  } catch {
  }
}
async function updateGuardclawStats(level) {
  try {
    let stats = { s1Count: 0, s2Count: 0, s3Count: 0, totalMessages: 0, s3Policy: "local-only", lastUpdated: null };
    try {
      const raw = await fs4.promises.readFile(GUARDCLAW_STATS_PATH, "utf8");
      Object.assign(stats, JSON.parse(raw));
    } catch {
    }
    if (level === "S1") stats.s1Count = stats.s1Count + 1;
    else if (level === "S2") stats.s2Count = stats.s2Count + 1;
    else if (level === "S3") stats.s3Count = stats.s3Count + 1;
    stats.totalMessages = stats.totalMessages + 1;
    stats.lastUpdated = (/* @__PURE__ */ new Date()).toISOString();
    await writeStatsAtomic(stats);
  } catch {
  }
}
function registerHooks(api) {
  const privacyCfgInit = getLiveConfig();
  const sessionBaseDir = privacyCfgInit.session?.baseDir;
  const memoryManager = getDefaultMemoryManager();
  memoryManager.initializeDirectories().catch((err) => {
    api.logger.error(`[GuardClaw] Failed to initialize memory directories: ${String(err)}`);
  });
  getDefaultSessionManager(sessionBaseDir);
  setInterval(async () => {
    try {
      await fs4.promises.access(GUARDCLAW_PENDING_CONFIG_PATH);
      const pendingRaw = await fs4.promises.readFile(GUARDCLAW_PENDING_CONFIG_PATH, "utf8");
      const pending = JSON.parse(pendingRaw);
      const s3Policy = pending.s3Policy;
      if (!s3Policy) return;
      const cfgRaw = await fs4.promises.readFile(GUARDCLAW_JSON_PATH2, "utf8");
      const cfg = JSON.parse(cfgRaw);
      if (!cfg.privacy) cfg.privacy = {};
      cfg.privacy.s3Policy = s3Policy;
      await fs4.promises.writeFile(GUARDCLAW_JSON_PATH2, JSON.stringify(cfg, null, 2));
      await fs4.promises.unlink(GUARDCLAW_PENDING_CONFIG_PATH);
      api.logger.info(`[GuardClaw] s3Policy updated to: ${s3Policy}`);
      try {
        const statsRaw = await fs4.promises.readFile(GUARDCLAW_STATS_PATH, "utf8");
        const stats = JSON.parse(statsRaw);
        stats.s3Policy = s3Policy;
        await fs4.promises.writeFile(GUARDCLAW_STATS_PATH, JSON.stringify(stats, null, 2));
      } catch {
      }
    } catch {
    }
  }, 5e3);
  api.on("before_model_resolve", async (event, ctx) => {
    try {
      const { prompt } = event;
      const sessionKey2 = ctx.sessionKey ?? "";
      if (!sessionKey2 || !prompt) return;
      clearActiveLocalRouting(sessionKey2);
      resetTurnLevel(sessionKey2);
      consumeDetection(sessionKey2);
      const privacyConfig = getLiveConfig();
      if (!privacyConfig.enabled) return;
      const budgetCfg = privacyConfig.budget;
      if (budgetCfg?.enabled) {
        const budgetStatus = checkBudget(budgetCfg);
        if (budgetStatus.exceeded) {
          const msg = `Budget cap exceeded \u2014 daily: $${budgetStatus.dailyCost.toFixed(4)}${budgetCfg.dailyCap ? `/$${budgetCfg.dailyCap}` : ""}, monthly: $${budgetStatus.monthlyCost.toFixed(4)}${budgetCfg.monthlyCap ? `/$${budgetCfg.monthlyCap}` : ""}`;
          api.logger.warn(`[GuardClaw] ${msg}`);
          const hooks = privacyConfig.webhooks ?? [];
          fireWebhooks("budget_exceeded", { sessionKey: sessionKey2, reason: msg }, hooks);
          if (budgetStatus.action === "block") {
            throw new Error(`[GuardClaw] Request blocked: ${msg}`);
          }
          if (budgetStatus.action === "pause_cloud") {
            api.logger.info("[GuardClaw] Budget exceeded \u2014 routing to local model");
            const guardCfg = getGuardAgentConfig(privacyConfig);
            const localProvider = guardCfg?.provider ?? privacyConfig.localModel?.provider ?? "ollama";
            return { providerOverride: localProvider, ...guardCfg?.modelName ? { modelOverride: guardCfg.modelName } : {} };
          }
        } else if (budgetStatus.warning) {
          const msg = `Budget warning \u2014 daily: $${budgetStatus.dailyCost.toFixed(4)}${budgetCfg.dailyCap ? `/$${budgetCfg.dailyCap}` : ""}, monthly: $${budgetStatus.monthlyCost.toFixed(4)}${budgetCfg.monthlyCap ? `/$${budgetCfg.monthlyCap}` : ""}`;
          api.logger.warn(`[GuardClaw] ${msg}`);
          const hooks = privacyConfig.webhooks ?? [];
          fireWebhooks("budget_warning", { sessionKey: sessionKey2, reason: msg }, hooks);
        }
      }
      if (isGuardSessionKey(sessionKey2)) {
        const guardInjCfg = getLiveInjectionConfig();
        if (guardInjCfg.enabled !== false) {
          const guardMsgStr = String(prompt);
          const guardContent = extractUserContent(guardMsgStr) ?? guardMsgStr;
          try {
            const guardInjResult = await detectInjection(guardContent, "user_message", guardInjCfg);
            if (guardInjResult.action === "block") {
              api.logger.warn(
                `[GuardClaw S0] BLOCKED guard session injection: session=${sessionKey2} score=${guardInjResult.score} patterns=${guardInjResult.matches.join(",")}`
              );
              recordDetection(sessionKey2, "S0", "onUserMessage", guardInjResult.blocked_reason ?? "Prompt injection in guard session");
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
          return { providerOverride: guardCfg.provider, ...guardCfg.modelName ? { modelOverride: guardCfg.modelName } : {} };
        }
        return;
      }
      if (ctx.workspaceDir) _cachedWorkspaceDir = ctx.workspaceDir;
      const msgStr = String(prompt);
      if (shouldSkipMessage(msgStr)) return;
      const s2ChannelSet = new Set(privacyConfig.s2Channels ?? []);
      const channelId = ctx.channelId ?? "";
      if (channelId && s2ChannelSet.has(channelId)) {
        gcDebug(api.logger, `[GuardClaw] s2Channels fast path: channel=${channelId}`);
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
        const { preRedactCredentials } = await import("./local-model-KE5A4PTC.js");
        const desensitized2 = redactSensitiveInfo(preRedactCredentials(msgStr), privacyConfig.redaction);
        recordDetection(sessionKey2, "S2", "onUserMessage", "s2Channels pre-classified");
        updateGuardclawStats("S2").catch(() => {
        });
        markSessionAsPrivate(sessionKey2, "S2");
        stashDetection(sessionKey2, {
          level: "S2",
          reason: "s2Channels pre-classified",
          desensitized: desensitized2,
          originalPrompt: msgStr,
          timestamp: Date.now()
        });
        const s2PolicyFast = privacyConfig.s2Policy ?? "proxy";
        if (s2PolicyFast === "local") {
          const guardCfgFast = getGuardAgentConfig(privacyConfig);
          const fastLocalProvider = privacyConfig.localModel?.provider ?? "ollama";
          gcDebug(api.logger, `[GuardClaw] s2Channels fast path \u2014 s2Policy=local, routing to ${guardCfgFast?.provider ?? fastLocalProvider}/${guardCfgFast?.modelName ?? privacyConfig.localModel?.model}`);
          return {
            providerOverride: guardCfgFast?.provider ?? fastLocalProvider,
            modelOverride: guardCfgFast?.modelName ?? privacyConfig.localModel?.model
          };
        }
        const defaults = api.config.agents?.defaults;
        const primaryModel = defaults?.model?.primary ?? "";
        const defaultProvider = defaults?.provider || primaryModel.split("/")[0] || "openai";
        const providerConfig = api.config.models?.providers?.[defaultProvider];
        if (providerConfig) {
          const pc = providerConfig;
          const providerApi = pc.api ?? void 0;
          stashOriginalProvider(sessionKey2, {
            baseUrl: pc.baseUrl ?? resolveDefaultBaseUrl(defaultProvider, providerApi),
            apiKey: pc.apiKey ?? "",
            provider: defaultProvider,
            api: providerApi
          });
        }
        return { providerOverride: "guardclaw-privacy" };
      }
      const injectionCfg = getLiveInjectionConfig();
      if (injectionCfg.enabled !== false) {
        let senderId = ctx.senderId;
        if (!senderId && ctx.channelId) {
          senderId = getLastSenderId(ctx.channelId);
          clearLastSenderId(ctx.channelId);
        }
        if (!senderId) {
          const senderMatch = msgStr.match(/"sender_id"\s*:\s*"(\d+)"/);
          if (senderMatch) senderId = senderMatch[1];
        }
        const bannedSet = new Set(injectionCfg.banned_senders ?? []);
        const isBannedSender = senderId && bannedSet.has(senderId);
        if (isBannedSender) {
          api.logger.warn(`[GuardClaw S0] BANNED sender blocked: senderId=${senderId} session=${sessionKey2}`);
          recordDetection(sessionKey2, "S0", "onUserMessage", `Banned sender: ${senderId}`);
          fireWebhooks("ban_triggered", { sessionKey: sessionKey2, reason: `Banned sender: ${senderId}`, details: { senderId: senderId ?? "" } }, privacyConfig.webhooks ?? []);
          throw new Error(`[GuardClaw S0] Message blocked: Sender ${senderId} is banned`);
        }
        const isExemptSender = senderId && new Set(injectionCfg.exempt_senders ?? []).has(senderId);
        if (isExemptSender) {
          gcDebug(api.logger, `[GuardClaw S0] Exempt sender bypass \u2014 skipping injection check: senderId=${senderId} session=${sessionKey2}`);
        }
        if (!isExemptSender) {
          const rawExtracted = extractUserContent(msgStr);
          const userContent = rawExtracted ? stripThreadContextPrefix(rawExtracted) : stripThreadContextPrefix(msgStr) || null;
          if (!userContent) {
            api.logger.debug?.(`[GuardClaw S0] Skipping injection check \u2014 no user content extracted`);
          } else {
            try {
              const injResult = await detectInjection(userContent, "user_message", injectionCfg);
              if (injResult.action === "block") {
                api.logger.warn(
                  `[GuardClaw S0] BLOCKED session=${sessionKey2} score=${injResult.score} patterns=${injResult.matches.join(",")}`
                );
                await appendInjectionLog({
                  ts: (/* @__PURE__ */ new Date()).toISOString(),
                  session: sessionKey2,
                  senderId,
                  action: "block",
                  score: injResult.score,
                  patterns: injResult.matches,
                  source: "user_message",
                  // GCF-011: Redact before logging — false-positive blocks may contain real secrets.
                  preview: redactSensitiveInfo(msgStr.slice(0, 80), getLiveConfig().redaction)
                });
                void updateS0Stats("block");
                if (senderId) {
                  const attempts = recordInjectionAttempt(senderId);
                  const alreadyBanned = bannedSet.has(senderId);
                  if (attempts >= 2 && !alreadyBanned && !pendingBans.has(senderId)) {
                    pendingBans.add(senderId);
                    api.logger.warn(`[GuardClaw S0] AUTO-BANNING senderId=${senderId} after ${attempts} injection attempts`);
                    const newBanned = [...injectionCfg.banned_senders ?? [], senderId];
                    updateLiveInjectionConfig({ banned_senders: newBanned });
                    withConfigWriteLock(async () => {
                      const raw = await fs4.promises.readFile(GUARDCLAW_JSON_PATH2, "utf8");
                      const cfg = JSON.parse(raw);
                      if (!cfg.privacy) cfg.privacy = {};
                      const privacy = cfg.privacy;
                      if (!privacy.injection) privacy.injection = {};
                      privacy.injection.banned_senders = newBanned;
                      await fs4.promises.writeFile(GUARDCLAW_JSON_PATH2, JSON.stringify(cfg, null, 2), { encoding: "utf-8", mode: 384 });
                    }).catch((err) => {
                      api.logger.warn(`[GuardClaw S0] Failed to persist ban for ${senderId}: ${String(err)}`);
                    }).finally(() => {
                      pendingBans.delete(senderId ?? "");
                    });
                  }
                }
                recordDetection(sessionKey2, "S0", "onUserMessage", injResult.blocked_reason ?? "Prompt injection detected");
                const alertChannel = injectionCfg.alert_channel ?? SECURITY_CHANNEL;
                const alertMsg = formatBlockAlert(injResult, "user_message", msgStr);
                void api.discord?.sendMessage?.(alertChannel, alertMsg)?.catch?.(() => {
                });
                throw new Error(
                  `[GuardClaw S0] Message blocked: ${injResult.blocked_reason ?? "Prompt injection detected"}`
                );
              } else if (injResult.action === "sanitise" && injResult.sanitised) {
                api.logger.warn(
                  `[GuardClaw S0] SANITISED session=${sessionKey2} score=${injResult.score} patterns=${injResult.matches.join(",")}`
                );
                await appendInjectionLog({
                  ts: (/* @__PURE__ */ new Date()).toISOString(),
                  session: sessionKey2,
                  action: "sanitise",
                  score: injResult.score,
                  patterns: injResult.matches,
                  source: "user_message",
                  // GCF-011: Redact before logging.
                  preview: redactSensitiveInfo(msgStr.slice(0, 80), getLiveConfig().redaction)
                });
                void updateS0Stats("sanitise");
                recordDetection(sessionKey2, "S0", "onUserMessage", `Injection sanitised (score ${Math.round(injResult.score)})`);
                const sanitiseRecheck = detectByRules(
                  { checkpoint: "onUserMessage", message: injResult.sanitised, sessionKey: sessionKey2 },
                  privacyConfig
                );
                if (sanitiseRecheck.level !== "S1") {
                  api.logger.warn(
                    `[GuardClaw S0] Sanitised content still triggers ${sanitiseRecheck.level} \u2014 escalating to block. reason=${sanitiseRecheck.reason}`
                  );
                  recordDetection(sessionKey2, "S0", "onUserMessage", `Post-sanitise escalation: ${sanitiseRecheck.reason}`);
                  throw new Error(`[GuardClaw S0] Message blocked after sanitise re-check: ${sanitiseRecheck.reason}`);
                }
                event.prompt = injResult.sanitised;
              }
            } catch (err) {
              const msg = String(err);
              api.logger.warn(`[GuardClaw S0] CATCH: ${msg}`);
              if (msg.includes("[GuardClaw S0] Message blocked")) throw err;
              api.logger.warn(`[GuardClaw S0] Detection error (non-fatal): ${msg}`);
            }
          }
        }
      }
      const rulePreCheck = detectByRules(
        { checkpoint: "onUserMessage", message: msgStr, sessionKey: sessionKey2 },
        privacyConfig
      );
      if (rulePreCheck.level === "S3") {
        recordDetection(sessionKey2, "S3", "onUserMessage", rulePreCheck.reason);
        updateGuardclawStats("S3").catch(() => {
        });
        trackSessionLevel(sessionKey2, "S3");
        const s3Policy = privacyConfig.s3Policy ?? "local-only";
        if (s3Policy === "redact-and-forward") {
          api.logger.warn(`[GuardClaw] S3 redact-and-forward mode \u2014 aggressively redacting before cloud`);
          stashDetection(sessionKey2, {
            level: "S2",
            // treat as S2 so desensitization pipeline runs
            reason: `s3-redact-forward: ${rulePreCheck.reason}`,
            originalPrompt: msgStr,
            timestamp: Date.now()
          });
          return;
        } else if (s3Policy === "synthesize") {
          gcDebug(api.logger, "[GuardClaw] S3 synthesize mode \u2014 processing locally before cloud");
          const taskContext = (params.messages ?? []).slice(-4).map((m) => `${m.role}: ${String(m.content).slice(0, 200)}`).join("\n");
          const _synthT0 = Date.now();
          const synthResult = await synthesizeContent(
            userMessage,
            taskContext,
            privacyConfig,
            sessionKey2
          );
          const _synthLatency = Date.now() - _synthT0;
          updateSynthesisStats("user_message", _synthLatency, synthResult.ok).catch(() => {
          });
          if (synthResult.ok) {
            gcDebug(api.logger, `[GuardClaw] S3 synthesis complete \u2014 forwarding to cloud (${_synthLatency}ms)`);
            if (sessionMgr) {
              sessionMgr.appendToFullHistory(sessionKey2, { role: "user", content: userMessage });
              sessionMgr.appendToCleanHistory(sessionKey2, { role: "user", content: synthResult.synthetic });
            }
            params.messages = (params.messages ?? []).map(
              (m, i, arr) => i === arr.length - 1 && m.role === "user" ? { ...m, content: synthResult.synthetic } : m
            );
          } else {
            api.logger.warn(`[GuardClaw] S3 synthesis failed (${synthResult.reason}) \u2014 falling back to local-only`);
            stashDetection(sessionKey2, { level: "S3", reason: `synthesis-fallback: ${synthResult.reason}` });
          }
        }
        setActiveLocalRouting(sessionKey2);
        registerGuardSessionParent(sessionKey2);
        stashDetection(sessionKey2, {
          level: "S3",
          reason: rulePreCheck.reason,
          originalPrompt: msgStr,
          timestamp: Date.now()
        });
        const guardCfg = getGuardAgentConfig(privacyConfig);
        const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
        const provider = guardCfg?.provider ?? defaultProvider;
        gcDebug(api.logger, `[GuardClaw] S3 (rule fast-path) \u2014 routing to ${provider}${guardCfg?.modelName ? "/" + guardCfg.modelName : ""}`);
        return { providerOverride: provider, ...guardCfg?.modelName ? { modelOverride: guardCfg.modelName } : {} };
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
          sessionKey: sessionKey2,
          agentId: ctx.agentId
        },
        getPipelineConfig()
      );
      recordDetection(sessionKey2, decision.level, "onUserMessage", decision.reason);
      updateGuardclawStats(decision.level).catch(() => {
      });
      gcDebug(api.logger, `[GuardClaw] ROUTE: session=${sessionKey2} level=${decision.level} action=${decision.action} target=${JSON.stringify(decision.target)} reason=${decision.reason}`);
      if (decision.level === "S3" || decision.level === "S2") {
        const webhooks = privacyConfig.webhooks ?? [];
        if (webhooks.length > 0) {
          const event2 = decision.level === "S3" ? "s3_detected" : "s2_detected";
          fireWebhooks(event2, { sessionKey: sessionKey2, level: decision.level, reason: decision.reason }, webhooks);
        }
      }
      if (decision.level === "S1" && decision.action === "passthrough") {
        return;
      }
      if (decision.level === "S2" && channelId && !s2ChannelSet.has(channelId)) {
        s2ChannelSet.add(channelId);
        const updatedChannels = [...s2ChannelSet];
        updateLiveConfig({ s2Channels: updatedChannels });
        withConfigWriteLock(async () => {
          try {
            const raw = await fs4.promises.readFile(GUARDCLAW_JSON_PATH2, "utf8");
            const cfg = JSON.parse(raw);
            if (!cfg.privacy) cfg.privacy = {};
            cfg.privacy.s2Channels = updatedChannels;
            await fs4.promises.writeFile(GUARDCLAW_JSON_PATH2, JSON.stringify(cfg, null, 2), { mode: 384 });
          } catch {
          }
        }).catch(() => {
        });
        api.logger.info(`[GuardClaw] Auto-learned S2 channel: ${channelId} (${updatedChannels.length} total)`);
      }
      if (decision.level === "S3") {
        trackSessionLevel(sessionKey2, "S3");
        setActiveLocalRouting(sessionKey2);
        registerGuardSessionParent(sessionKey2);
        stashDetection(sessionKey2, {
          level: "S3",
          reason: decision.reason,
          originalPrompt: msgStr,
          timestamp: Date.now()
        });
        if (decision.target) {
          gcDebug(api.logger, `[GuardClaw] S3 \u2014 routing to ${decision.target.provider}/${decision.target.model} [${decision.routerId}]`);
          return {
            providerOverride: decision.target.provider,
            ...decision.target.model ? { modelOverride: decision.target.model } : {}
          };
        }
        const guardCfg = getGuardAgentConfig(privacyConfig);
        const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
        gcDebug(api.logger, `[GuardClaw] S3 \u2014 routing to ${guardCfg?.provider ?? defaultProvider}${guardCfg?.modelName ? "/" + guardCfg.modelName : ""} [${decision.routerId}]`);
        return {
          providerOverride: guardCfg?.provider ?? defaultProvider,
          ...guardCfg?.modelName ? { modelOverride: guardCfg.modelName } : {}
        };
      }
      if (decision.level === "S2") {
        const requestedModel = event.model ?? "";
        const requestedProvider = requestedModel.includes("/") ? requestedModel.split("/")[0] : "";
        const allLocalProviders = privacyConfig.localProviders ?? [];
        if (requestedProvider && isLocalProvider(requestedProvider, allLocalProviders)) {
          gcDebug(api.logger, `[GuardClaw] S2 skip \u2014 original model "${requestedModel}" is already local, no proxy needed`);
          recordDetection(sessionKey2, "S2", "onUserMessage", `${decision.reason}; local model \u2014 proxy skipped`);
          updateGuardclawStats("S2").catch(() => {
          });
          markSessionAsPrivate(sessionKey2, "S2");
          return;
        }
      }
      let desensitized;
      if (decision.level === "S2") {
        const result = await desensitizeWithLocalModel(msgStr, privacyConfig, sessionKey2);
        if (result.failed) {
          api.logger.warn("[GuardClaw] S2 desensitization failed \u2014 escalating to S3 (local-only) to prevent PII leak");
          trackSessionLevel(sessionKey2, "S3");
          setActiveLocalRouting(sessionKey2);
          registerGuardSessionParent(sessionKey2);
          stashDetection(sessionKey2, {
            level: "S3",
            reason: `${decision.reason}; desensitization failed \u2014 escalated to S3`,
            originalPrompt: msgStr,
            timestamp: Date.now()
          });
          const guardCfg = getGuardAgentConfig(privacyConfig);
          const fallbackProvider = privacyConfig.localModel?.provider ?? "ollama";
          return {
            providerOverride: guardCfg?.provider ?? fallbackProvider,
            ...guardCfg?.modelName ? { modelOverride: guardCfg.modelName } : {}
          };
        }
        desensitized = result.desensitized;
      }
      stashDetection(sessionKey2, {
        level: decision.level,
        reason: decision.reason,
        desensitized,
        originalPrompt: msgStr,
        timestamp: Date.now()
      });
      if (decision.level === "S2" && decision.action === "redirect" && decision.target?.provider !== "guardclaw-privacy") {
        markSessionAsPrivate(sessionKey2, decision.level);
        if (decision.target) {
          gcDebug(api.logger, `[GuardClaw] S2 \u2014 routing to ${decision.target.provider}/${decision.target.model} [${decision.routerId}]`);
          return {
            providerOverride: decision.target.provider,
            ...decision.target.model ? { modelOverride: decision.target.model } : {}
          };
        }
      }
      if (decision.level === "S2" && decision.target?.provider === "guardclaw-privacy") {
        markSessionAsPrivate(sessionKey2, "S2");
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
          stashOriginalProvider(sessionKey2, stashTarget);
        }
        const modelInfo = decision.target.model ? ` (model=${decision.target.model})` : "";
        gcDebug(api.logger, `[GuardClaw] S2 \u2014 routing through privacy proxy${modelInfo} [${decision.routerId}]`);
        return {
          providerOverride: "guardclaw-privacy",
          ...decision.target.model ? { modelOverride: decision.target.model } : {}
        };
      }
      if (decision.action === "redirect" && decision.target) {
        gcDebug(api.logger, `[GuardClaw] ${decision.level} \u2014 custom route to ${decision.target.provider}/${decision.target.model} [${decision.routerId}]`);
        return {
          providerOverride: decision.target.provider,
          ...decision.target.model ? { modelOverride: decision.target.model } : {}
        };
      }
      if (decision.action === "block") {
        if (decision.level === "S3") {
          trackSessionLevel(sessionKey2, "S3");
          setActiveLocalRouting(sessionKey2);
        } else {
          markSessionAsPrivate(sessionKey2, decision.level);
        }
        const guardCfg = getGuardAgentConfig(privacyConfig);
        const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
        api.logger.warn(`[GuardClaw] ${decision.level} BLOCK \u2014 redirecting to edge model [${decision.routerId}]`);
        return {
          providerOverride: guardCfg?.provider ?? defaultProvider,
          ...guardCfg?.modelName ? { modelOverride: guardCfg.modelName } : {}
        };
      }
      if (decision.action === "transform") {
        if (decision.level === "S3") {
          trackSessionLevel(sessionKey2, "S3");
          setActiveLocalRouting(sessionKey2);
          registerGuardSessionParent(sessionKey2);
          stashDetection(sessionKey2, {
            level: "S3",
            reason: decision.reason,
            originalPrompt: msgStr,
            timestamp: Date.now()
          });
          const guardCfg = getGuardAgentConfig(privacyConfig);
          const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
          gcDebug(api.logger, `[GuardClaw] S3 TRANSFORM \u2014 routing to edge model [${decision.routerId}]`);
          return {
            providerOverride: guardCfg?.provider ?? defaultProvider,
            ...guardCfg?.modelName ? { modelOverride: guardCfg.modelName } : {}
          };
        }
        if (decision.level === "S2") {
          const transformedText = decision.transformedContent ?? desensitized ?? msgStr;
          stashDetection(sessionKey2, {
            level: "S2",
            reason: decision.reason,
            desensitized: transformedText,
            originalPrompt: msgStr,
            timestamp: Date.now()
          });
          markSessionAsPrivate(sessionKey2, "S2");
          const s2Policy = privacyConfig.s2Policy ?? "proxy";
          if (s2Policy === "local") {
            const guardCfg = getGuardAgentConfig(privacyConfig);
            const defaultProvider2 = privacyConfig.localModel?.provider ?? "ollama";
            gcDebug(api.logger, `[GuardClaw] S2 TRANSFORM \u2014 routing to local ${guardCfg?.provider ?? defaultProvider2} [${decision.routerId}]`);
            return {
              providerOverride: guardCfg?.provider ?? defaultProvider2,
              ...guardCfg?.modelName ? { modelOverride: guardCfg.modelName } : {}
            };
          }
          const defaults = api.config.agents?.defaults;
          const primaryModel = defaults?.model?.primary ?? "";
          const defaultProvider = defaults?.provider || primaryModel.split("/")[0] || "openai";
          const providerConfig = api.config.models?.providers?.[defaultProvider];
          if (providerConfig) {
            const pc = providerConfig;
            const providerApi = pc.api ?? void 0;
            stashOriginalProvider(sessionKey2, {
              baseUrl: pc.baseUrl ?? resolveDefaultBaseUrl(defaultProvider, providerApi),
              apiKey: pc.apiKey ?? "",
              provider: defaultProvider,
              api: providerApi
            });
          }
          gcDebug(api.logger, `[GuardClaw] S2 TRANSFORM \u2014 routing through privacy proxy [${decision.routerId}]`);
          return { providerOverride: "guardclaw-privacy" };
        }
        return;
      }
      return;
    } catch (err) {
      const errMsg = String(err);
      if (errMsg.includes("[GuardClaw S0]") || errMsg.includes("[GuardClaw] Request blocked")) throw err;
      api.logger.error(`[GuardClaw] Pipeline error \u2014 failing safe to local model: ${errMsg}`);
      try {
        const safeCfg = getLiveConfig();
        const safeGuardCfg = getGuardAgentConfig(safeCfg);
        const safeProvider = safeGuardCfg?.provider ?? safeCfg.localModel?.provider ?? "ollama";
        const safeModel = safeGuardCfg?.modelName ?? safeCfg.localModel?.model ?? "llama3.2:3b";
        return { providerOverride: safeProvider, modelOverride: safeModel };
      } catch {
        throw new Error("[GuardClaw] Pipeline error and failsafe failed \u2014 request blocked for safety");
      }
    }
  });
  api.on("before_prompt_build", async (_event, ctx) => {
    const sessionKey2 = ctx.sessionKey ?? "";
    try {
      if (!sessionKey2) return;
      const pending = getPendingDetection(sessionKey2);
      if (!pending || pending.level === "S1") return;
      const privacyConfig = getLiveConfig();
      const sessionCfg = privacyConfig.session ?? {};
      const shouldInject = sessionCfg.injectDualHistory !== false && sessionCfg.isolateGuardHistory !== false;
      const historyLimit = sessionCfg.historyLimit ?? 20;
      if (pending.level === "S3") {
        if (shouldInject) {
          const context = await loadDualTrackContext(sessionKey2, ctx.agentId, historyLimit);
          if (context) {
            gcDebug(api.logger, `[GuardClaw] Injected dual-track history context for S3 turn`);
            return { prependContext: context };
          }
        }
        return;
      }
      const s2Policy = privacyConfig.s2Policy ?? "proxy";
      if (pending.level === "S2" && s2Policy === "local") {
        if (shouldInject) {
          const context = await loadDualTrackContext(sessionKey2, ctx.agentId, historyLimit);
          if (context) {
            gcDebug(api.logger, `[GuardClaw] Injected dual-track history context for S2-local turn`);
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
      try {
        const pendingOnErr = getPendingDetection(sessionKey2);
        if (pendingOnErr?.level === "S2") {
          const s2PolicyOnErr = getLiveConfig().s2Policy ?? "proxy";
          if (s2PolicyOnErr === "proxy") {
            api.logger.warn(
              `[GuardClaw] SECURITY: before_prompt_build error during S2-proxy \u2014 markers not injected, PII may pass through proxy unstripped (session=${sessionKey2})`
            );
          }
        }
      } catch {
      }
      api.logger.error(`[GuardClaw] Error in before_prompt_build hook: ${String(err)}`);
    }
  });
  api.on("before_tool_call", async (event, ctx) => {
    try {
      const { toolName, params: params2 } = event;
      const sessionKey2 = ctx.sessionKey ?? "";
      if (!toolName) return;
      const typedParams = params2;
      const privacyConfig = getLiveConfig();
      const baseDir = privacyConfig.session?.baseDir ?? "~/.openclaw";
      const baConfig = privacyConfig.behavioralAttestation;
      if (baConfig?.enabled && !isVerifiedGuardSession(sessionKey2)) {
        const currentLevel = getPendingDetection(sessionKey2)?.level ?? null;
        logToolEvent(sessionKey2, toolName, typedParams, currentLevel);
      }
      if (toolName === "use_secret") {
        const secretResult = await handleUseSecret(
          typedParams,
          sessionKey2,
          privacyConfig,
          privacyConfig.webhooks,
          api.logger
        );
        if (!secretResult.ok) {
          return {
            block: true,
            blockReason: `[GuardClaw:secrets] Access denied \u2014 ${secretResult.reason}`
          };
        }
        return {
          block: true,
          blockReason: `[GuardClaw:secrets] Operation succeeded
---
${secretResult.result}`
        };
      }
      if (isVerifiedGuardSession(sessionKey2)) {
        try {
          if (isNetworkTool(toolName)) {
            api.logger.warn(
              `[GuardClaw] BLOCKED guard session network tool: ${toolName} (session=${sessionKey2})`
            );
            return {
              block: true,
              blockReason: `GuardClaw: network tools are blocked in guard sessions to prevent secret exfiltration (${toolName})`
            };
          }
          const bashCmd = String(typedParams.command ?? typedParams.cmd ?? typedParams.script ?? "");
          if (bashCmd && parseKeychainCommand(bashCmd)) {
            markKeychainFetchPending(sessionKey2);
            gcDebug(api.logger, `[GuardClaw] Guard session keychain fetch detected \u2014 result will be tracked (session=${sessionKey2})`);
          }
          if (isExecTool(toolName) && bashCmd) {
            const networkTool = isGuardNetworkCommand(bashCmd);
            if (networkTool) {
              api.logger.warn(
                `[GuardClaw] BLOCKED guard session network command via bash: ${networkTool} (session=${sessionKey2})`
              );
              return {
                block: true,
                blockReason: `GuardClaw: outbound network commands are blocked in guard sessions to prevent secret exfiltration (${networkTool})`
              };
            }
          }
          const paramStr = JSON.stringify(typedParams);
          if (containsTrackedSecret(sessionKey2, paramStr)) {
            api.logger.warn(
              `[GuardClaw] BLOCKED guard session tool "${toolName}": params contain a tracked secret (session=${sessionKey2})`
            );
            return {
              block: true,
              blockReason: `GuardClaw: tool parameters contain a tracked Keychain secret and cannot be called in this context (${toolName})`
            };
          }
        } catch (guardErr) {
          api.logger.error(`[GuardClaw] Guard session check error \u2014 blocking tool for safety: ${String(guardErr)} (tool=${toolName}, session=${sessionKey2})`);
          return {
            block: true,
            blockReason: `GuardClaw: safety check error in guard session \u2014 tool blocked for safety (${toolName})`
          };
        }
      }
      if (!isVerifiedGuardSession(sessionKey2) && !isActiveLocalRouting(sessionKey2)) {
        const pathValues = extractPathsFromParams(typedParams);
        for (const p of pathValues) {
          if (isProtectedMemoryPath(p, baseDir)) {
            api.logger.warn(`[GuardClaw] BLOCKED: cloud model tried to access protected path: ${p}`);
            return { block: true, blockReason: `GuardClaw: access to full history/memory is restricted for cloud models (${p})` };
          }
        }
        const s3Paths = privacyConfig.rules?.tools?.S3?.paths ?? [];
        for (const p of pathValues) {
          if (isSecretsMountPath(p)) {
            api.logger.warn(
              `[GuardClaw GCF-004] BLOCKED cloud-session tool "${toolName}": secrets-mount path "${p}" \u2014 would expose secrets to cloud model (session=${sessionKey2})`
            );
            return {
              block: true,
              blockReason: `GuardClaw: secrets-mount paths are not accessible from cloud-model sessions \u2014 use a guard session for sensitive file access (${p})`
            };
          }
          if (s3Paths.length > 0 && matchesPathPattern(p, s3Paths)) {
            api.logger.warn(
              `[GuardClaw GCF-004] BLOCKED cloud-session tool "${toolName}": S3 path "${p}" \u2014 would expose sensitive data to cloud model (session=${sessionKey2})`
            );
            return {
              block: true,
              blockReason: `GuardClaw: S3 path access is blocked for cloud-model sessions \u2014 use a guard session for sensitive file operations (${p})`
            };
          }
        }
        const _taintBtcCfg = privacyConfig.taintTracking;
        if (_taintBtcCfg?.enabled !== false) {
          for (const p of pathValues) {
            if (isSecretsMountPath(p)) {
              markPendingTaint(sessionKey2, `secrets-file:${p}`, "S3");
              gcDebug(api.logger, `[GuardClaw:taint] Secrets-mount read detected \u2014 result will be taint-tracked (path=${p}, session=${sessionKey2})`);
            }
          }
        }
      }
      if (toolName === "memory_get" && shouldUseFullMemoryTrack(sessionKey2)) {
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
            { checkpoint: "onToolCallProposed", message: contentField, toolName, toolParams: typedParams, sessionKey: sessionKey2 },
            privacyConfig
          );
          recordDetection(sessionKey2, ruleResult.level, "onToolCallProposed", ruleResult.reason);
          updateGuardclawStats(ruleResult.level).catch(() => {
          });
          if (ruleResult.level === "S3") {
            trackSessionLevel(sessionKey2, "S3");
            return { block: true, blockReason: `GuardClaw: ${isSpawn ? "subagent task" : "A2A message"} blocked \u2014 S3 (${ruleResult.reason ?? "sensitive"})` };
          }
          if (ruleResult.level === "S2") {
            markSessionAsPrivate(sessionKey2, "S2");
          }
        }
      }
      if (isExecTool(toolName) && !isActiveLocalRouting(sessionKey2) && !isVerifiedGuardSession(sessionKey2)) {
        const command = String(typedParams.command ?? typedParams.cmd ?? typedParams.script ?? "");
        if (command) {
          const blocked = isHighRiskExecCommand(command);
          if (blocked) {
            api.logger.warn(`[GuardClaw] BLOCKED high-risk exec command: ${command.slice(0, 80)}`);
            recordDetection(sessionKey2, "S3", "onToolCallProposed", `high-risk exec: ${blocked}`);
            updateGuardclawStats("S3").catch(() => {
            });
            trackSessionLevel(sessionKey2, "S3");
            return { block: true, blockReason: `GuardClaw: exec command blocked \u2014 likely to output secrets (${blocked}). Use a local model session for this operation.` };
          }
        }
      }
      if (!isActiveLocalRouting(sessionKey2) && !isToolAllowlisted(toolName)) {
        const detectors = privacyConfig.checkpoints?.onToolCallProposed ?? ["ruleDetector"];
        const usePipeline = detectors.includes("localModelDetector");
        let level = "S1";
        let reason;
        if (usePipeline) {
          const pipeline = getGlobalPipeline();
          if (pipeline) {
            const decision = await pipeline.run(
              "onToolCallProposed",
              { checkpoint: "onToolCallProposed", toolName, toolParams: typedParams, sessionKey: sessionKey2 },
              getPipelineConfig()
            );
            level = decision.level;
            reason = decision.reason;
          }
        } else {
          const ruleResult = detectByRules(
            { checkpoint: "onToolCallProposed", toolName, toolParams: typedParams, sessionKey: sessionKey2 },
            privacyConfig
          );
          level = ruleResult.level;
          reason = ruleResult.reason;
        }
        recordDetection(sessionKey2, level, "onToolCallProposed", reason);
        updateGuardclawStats(level).catch(() => {
        });
        if (level === "S3") {
          trackSessionLevel(sessionKey2, "S3");
          return { block: true, blockReason: `GuardClaw: tool "${toolName}" blocked \u2014 S3 (${reason ?? "sensitive"})` };
        }
        if (level === "S2") {
          markSessionAsPrivate(sessionKey2, "S2");
        }
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_tool_call hook: ${String(err)}`);
    }
  });
  api.on("after_tool_call", async (event, ctx) => {
    try {
      const sessionKey2 = ctx.sessionKey ?? "";
      if (!sessionKey2) return;
      const privacyConfig = getLiveConfig();
      if ((privacyConfig.s3Policy ?? "local-only") !== "synthesize") return;
      if (!privacyConfig.localModel?.enabled) return;
      if (isActiveLocalRouting(sessionKey2)) return;
      if (isVerifiedGuardSession(sessionKey2)) return;
      if (ctx.toolName && isToolAllowlisted(ctx.toolName)) return;
      const ev = event;
      const raw = ev.output ?? ev.result ?? ev.text ?? ev.content ?? "";
      const textContent = typeof raw === "string" ? raw : JSON.stringify(raw);
      if (!textContent || textContent.length < 10) return;
      const ruleCheck = detectByRules(
        { checkpoint: "onToolCallExecuted", toolName: ctx.toolName, toolResult: textContent, sessionKey: sessionKey2 },
        privacyConfig
      );
      if (ruleCheck.level !== "S3") return;
      gcDebug(api.logger, `[GuardClaw] S3 in tool result \u2014 synthesizing before tool_result_persist (tool=${ctx.toolName ?? "unknown"})`);
      const taskContext = `Tool "${ctx.toolName ?? "unknown"}" returned a result that needs to stay private.`;
      const _synthT0 = Date.now();
      const synthResult = await synthesizeToolResult(
        ctx.toolName ?? "unknown",
        textContent,
        taskContext,
        privacyConfig,
        sessionKey2
      );
      const _synthLatency = Date.now() - _synthT0;
      updateSynthesisStats("tool_result", _synthLatency, synthResult.ok).catch(() => {
      });
      if (synthResult.ok) {
        const queue = _synthesisPendingQueue.get(sessionKey2) ?? [];
        queue.push({ toolName: ctx.toolName ?? "", synthetic: synthResult.synthetic });
        _synthesisPendingQueue.set(sessionKey2, queue);
        gcDebug(api.logger, `[GuardClaw] Synthesis stashed for tool_result_persist \u2014 ${_synthLatency}ms (tool=${ctx.toolName ?? "unknown"})`);
      } else {
        api.logger.warn(`[GuardClaw] Tool result synthesis failed after ${_synthLatency}ms (${synthResult.reason}) \u2014 tool_result_persist will redact normally`);
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in after_tool_call synthesis: ${String(err)}`);
    }
  });
  api.on("after_tool_call", async (event, ctx) => {
    try {
      const sessionKey2 = ctx.sessionKey ?? "";
      if (!sessionKey2) return;
      if (isActiveLocalRouting(sessionKey2)) return;
      if (isVerifiedGuardSession(sessionKey2)) return;
      if (ctx.toolName && isToolAllowlisted(ctx.toolName)) return;
      const injectionCfg = getLiveInjectionConfig();
      if (injectionCfg.enabled === false) return;
      const ev = event;
      const raw = ev.output ?? ev.result ?? ev.text ?? ev.content ?? "";
      const textContent = typeof raw === "string" ? raw : JSON.stringify(raw);
      if (!textContent || textContent.length < 20) return;
      const toolName = ctx.toolName ?? "";
      let source = "api_response";
      if (/web.?fetch|http.?fetch/i.test(toolName)) source = "web_fetch";
      else if (/read.?file|file.?read/i.test(toolName)) source = "file";
      const injResult = await detectInjection(textContent, source, injectionCfg);
      if (injResult.action === "block" || injResult.action === "sanitise") {
        api.logger.warn(
          `[GuardClaw S0] DeBERTa audit: tool result injection confirmed: tool=${toolName} score=${injResult.score} patterns=${injResult.matches.join(",")} session=${sessionKey2}`
        );
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in after_tool_call injection check: ${String(err)}`);
    }
  });
  api.on("tool_result_persist", (event, ctx) => {
    const sessionKey2 = ctx.sessionKey ?? "";
    const msg = event.message;
    try {
      if (!sessionKey2) return;
      if (!msg) return;
      if (ctx.toolName === "write" || ctx.toolName === "write_file") {
        const writePath = String(event.params?.path ?? "");
        if (writePath && isMemoryWritePath(writePath)) {
          const workspaceDir = _cachedWorkspaceDir ?? process.cwd();
          const privacyConfig2 = getLiveConfig();
          const writePromise = syncMemoryWrite(writePath, workspaceDir, privacyConfig2, api.logger, isVerifiedGuardSession(sessionKey2)).catch((err) => {
            api.logger.warn(`[GuardClaw] Memory dual-write sync failed: ${String(err)}`);
          });
          trackMemoryWrite(sessionKey2, writePromise);
        }
      }
      if (ctx.toolName === "memory_search") {
        const filtered = filterMemorySearchResults(msg, shouldUseFullMemoryTrack(sessionKey2));
        if (filtered) return { message: filtered };
        return;
      }
      if (isActiveLocalRouting(sessionKey2)) {
        const textContent2 = extractMessageText(msg);
        if (textContent2 && textContent2.length >= 10) {
          const sessionManager = getDefaultSessionManager();
          const redacted2 = redactForCleanTranscript(textContent2, getLiveConfig().redaction);
          if (redacted2 !== textContent2) {
            gcDebug(api.logger, `[GuardClaw] S3 tool result PII-redacted for transcript (tool=${ctx.toolName ?? "unknown"})`);
            sessionManager.writeToClean(sessionKey2, {
              role: "tool",
              content: redacted2,
              timestamp: Date.now(),
              sessionKey: sessionKey2
            }).catch(() => {
            });
            const modified = replaceMessageText(msg, redacted2);
            if (modified) return { message: modified };
          } else {
            sessionManager.writeToClean(sessionKey2, {
              role: "tool",
              content: textContent2,
              timestamp: Date.now(),
              sessionKey: sessionKey2
            }).catch(() => {
            });
          }
        }
        return;
      }
      if (isVerifiedGuardSession(sessionKey2)) {
        const resultText = extractMessageText(msg);
        if (resultText) {
          if (consumeKeychainFetchPending(sessionKey2)) {
            const secretValue = resultText.trim();
            trackSecret(sessionKey2, secretValue);
            gcDebug(api.logger, `[GuardClaw] Guard session Keychain secret tracked (session=${sessionKey2})`);
            const redactedResult = redactTrackedSecrets(sessionKey2, resultText);
            if (redactedResult !== resultText) {
              const modified = replaceMessageText(msg, redactedResult);
              if (modified) return { message: modified };
            }
          } else {
            const redactedResult = redactTrackedSecrets(sessionKey2, resultText);
            if (redactedResult !== resultText) {
              const modified = replaceMessageText(msg, redactedResult);
              if (modified) return { message: modified };
            }
          }
        }
        return;
      }
      if (ctx.toolName && isToolAllowlisted(ctx.toolName)) return;
      const textContent = extractMessageText(msg);
      if (!textContent || textContent.length < 10) return;
      if (textContent.length < 200 && isToolNoise(textContent, ctx.toolName)) {
        if (isSessionMarkedPrivate(sessionKey2)) {
          const sessionManager = getDefaultSessionManager();
          sessionManager.writeToClean(sessionKey2, {
            role: "tool",
            content: textContent,
            timestamp: Date.now(),
            sessionKey: sessionKey2
          }).catch(() => {
          });
        }
        return;
      }
      {
        const rollingBuf = appendToRollingBuffer(sessionKey2, textContent);
        if (rollingBuf.length >= 10) {
          const rollingPrivCfg = getLiveConfig();
          const rollingCheck = detectByRules(
            { checkpoint: "onToolCallExecuted", toolName: ctx.toolName, toolResult: rollingBuf, sessionKey: sessionKey2 },
            rollingPrivCfg
          );
          if (rollingCheck.level === "S2" || rollingCheck.level === "S3") {
            api.logger.warn(
              `[GuardClaw:rolling] Cross-turn sensitive content detected level=${rollingCheck.level} session=${sessionKey2} reason=${rollingCheck.reason ?? ""}`
            );
            markSessionAsPrivate(sessionKey2, rollingCheck.level);
            recordDetection(sessionKey2, rollingCheck.level, "onToolCallExecuted", `[rolling-buffer] ${rollingCheck.reason ?? ""}`);
          }
        }
      }
      const injectionCfgTrp = getLiveInjectionConfig();
      if (injectionCfgTrp.enabled !== false) {
        const toolNameTrp = ctx.toolName ?? "";
        let sourceTrp = "api_response";
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
              ts: (/* @__PURE__ */ new Date()).toISOString(),
              session: sessionKey2,
              action: injAction,
              score: heuristic.score,
              patterns: heuristic.matches,
              source: sourceTrp,
              preview: redactSensitiveInfo(textContent.slice(0, 80), getLiveConfig().redaction)
            });
            void updateS0Stats(injAction);
            recordDetection(sessionKey2, "S0", "onToolCallExecuted", injReason);
            if (injAction === "block") {
              api.logger.warn(
                `[GuardClaw S0] Tool result blocked (injection heuristics): tool=${toolNameTrp} score=${heuristic.score} session=${sessionKey2}`
              );
              const blocked = replaceMessageText(
                msg,
                `[GuardClaw S0: Tool result blocked \u2014 prompt injection detected. Score: ${heuristic.score}, patterns: ${heuristic.matches.join(", ")}]`
              );
              if (blocked) return { message: blocked };
            } else {
              gcDebug(
                api.logger,
                `[GuardClaw S0] Tool result sanitised (injection heuristics): tool=${toolNameTrp} score=${heuristic.score} session=${sessionKey2}`
              );
              const sanitisedText = sanitiseContent(textContent, heuristic.matchedPatterns);
              const sanitised = replaceMessageText(msg, sanitisedText);
              if (sanitised) return { message: sanitised };
            }
          }
        }
      }
      const privacyConfig = getLiveConfig();
      const wasPrivateBefore = isSessionMarkedPrivate(sessionKey2);
      const _taintCfg = privacyConfig.taintTracking;
      const taintEnabled = _taintCfg?.enabled !== false;
      const taintMinLen = _taintCfg?.minValueLength ?? 8;
      if (taintEnabled) {
        const pendingTaint = consumePendingTaint(sessionKey2);
        if (pendingTaint) {
          const taintVals = extractTaintValues(textContent, taintMinLen);
          for (const v of taintVals) {
            registerTaint(sessionKey2, v, pendingTaint.source, pendingTaint.sensitivity, taintMinLen);
          }
          if (taintVals.length > 0) {
            gcDebug(
              api.logger,
              `[GuardClaw:taint] Registered ${taintVals.length} tainted value(s) from ${pendingTaint.source} (session=${sessionKey2})`
            );
          }
        }
      }
      const ruleCheck = detectByRules(
        {
          checkpoint: "onToolCallExecuted",
          toolName: ctx.toolName,
          toolResult: textContent,
          sessionKey: sessionKey2
        },
        privacyConfig
      );
      const detectedSensitive = ruleCheck.level === "S3" || ruleCheck.level === "S2";
      const effectiveLevel = ruleCheck.level === "S3" ? "S2" : ruleCheck.level;
      if (detectedSensitive) {
        trackSessionLevel(sessionKey2, ruleCheck.level);
        markSessionAsPrivate(sessionKey2, effectiveLevel);
        recordDetection(sessionKey2, ruleCheck.level, "onToolCallExecuted", ruleCheck.reason);
        updateGuardclawStats(ruleCheck.level).catch(() => {
        });
        if (ruleCheck.level === "S3") {
          api.logger.warn(
            `[GuardClaw] S3 detected in tool result AFTER cloud model already active \u2014 degrading to S2 (PII redaction). tool=${ctx.toolName ?? "unknown"}, reason=${ruleCheck.reason ?? "rule-match"}`
          );
        }
      }
      if (taintEnabled && (ruleCheck.level === "S3" || ruleCheck.level === "S2" && _taintCfg?.trackS2)) {
        const taintValsFromResult = extractTaintValues(textContent, taintMinLen);
        const taintSource = `${ruleCheck.level.toLowerCase()}-tool-result:${ctx.toolName ?? "unknown"}`;
        const taintSens = ruleCheck.level === "S3" ? "S3" : "S2";
        for (const v of taintValsFromResult) {
          registerTaint(sessionKey2, v, taintSource, taintSens, taintMinLen);
        }
        if (taintValsFromResult.length > 0) {
          gcDebug(
            api.logger,
            `[GuardClaw:taint] Registered ${taintValsFromResult.length} tainted value(s) from ${ruleCheck.level} tool result (tool=${ctx.toolName ?? "unknown"}, session=${sessionKey2})`
          );
        }
      }
      if (ruleCheck.level === "S3" && (privacyConfig.s3Policy ?? "local-only") === "synthesize") {
        const synthetic = _popSynthesisPending(sessionKey2, ctx.toolName ?? "");
        if (synthetic) {
          const sessionManager = getDefaultSessionManager();
          sessionManager.writeToClean(sessionKey2, { role: "tool", content: synthetic, timestamp: Date.now(), sessionKey: sessionKey2 }).catch(() => {
          });
          gcDebug(api.logger, `[GuardClaw] S3 tool result replaced with synthesis (tool=${ctx.toolName ?? "unknown"})`);
          const modified = replaceMessageText(msg, synthetic);
          if (modified) return { message: modified };
        }
      }
      const redacted = redactForCleanTranscript(textContent, getLiveConfig().redaction);
      const wasRedacted = redacted !== textContent;
      if (detectedSensitive || wasRedacted || wasPrivateBefore) {
        const sessionManager = getDefaultSessionManager();
        sessionManager.writeToClean(sessionKey2, {
          role: "tool",
          content: wasRedacted ? redacted : textContent,
          timestamp: Date.now(),
          sessionKey: sessionKey2
        }).catch(() => {
        });
      }
      if (wasRedacted) {
        if (!detectedSensitive) markSessionAsPrivate(sessionKey2, "S2");
        gcDebug(api.logger, `[GuardClaw] PII-redacted tool result for transcript (tool=${ctx.toolName ?? "unknown"})`);
        const modified = replaceMessageText(msg, redacted);
        if (modified) return { message: modified };
      }
      const skipSyncLlm = wasPrivateBefore || detectedSensitive;
      if (privacyConfig.localModel?.enabled && ruleCheck.level !== "S3" && !skipSyncLlm) {
        const llmResult = syncDetectByLocalModel(
          { checkpoint: "onToolCallExecuted", toolName: ctx.toolName, toolResult: textContent, sessionKey: sessionKey2 },
          privacyConfig
        );
        if (llmResult.level !== "S1" && llmResult.levelNumeric > ruleCheck.levelNumeric) {
          const llmEffective = llmResult.level === "S3" ? "S2" : llmResult.level;
          trackSessionLevel(sessionKey2, llmResult.level);
          if (!detectedSensitive) {
            markSessionAsPrivate(sessionKey2, llmEffective);
          }
          recordDetection(sessionKey2, llmResult.level, "onToolCallExecuted", llmResult.reason);
          updateGuardclawStats(llmResult.level).catch(() => {
          });
          if (llmResult.level === "S3") {
            api.logger.warn(
              `[GuardClaw] LLM elevated tool result to S3 \u2014 PII redacted before reaching cloud model. tool=${ctx.toolName ?? "unknown"}, reason=${llmResult.reason ?? "semantic"}`
            );
          } else {
            gcDebug(api.logger, `[GuardClaw] LLM elevated tool result to ${llmResult.level} (tool=${ctx.toolName ?? "unknown"}, reason=${llmResult.reason ?? "semantic"})`);
          }
          if (!detectedSensitive && !wasRedacted && !wasPrivateBefore) {
            const sessionManager = getDefaultSessionManager();
            const ts = Date.now();
            sessionManager.writeToClean(sessionKey2, { role: "tool", content: redacted, timestamp: ts, sessionKey: sessionKey2 }).catch(() => {
            });
          }
          if (llmResult.level === "S3") {
            const s3Redacted = wasRedacted ? redacted : redactForCleanTranscript(textContent, getLiveConfig().redaction);
            const modified = replaceMessageText(msg, s3Redacted);
            if (modified) return { message: modified };
          }
        }
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in tool_result_persist hook \u2014 attempting emergency redaction: ${String(err)}`);
      if (msg) {
        try {
          const emergencyText = extractMessageText(msg);
          if (emergencyText) {
            const emergencyRedacted = redactForCleanTranscript(emergencyText, getLiveConfig().redaction);
            if (emergencyRedacted !== emergencyText) {
              api.logger.warn(`[GuardClaw] Emergency redaction applied to tool result (session=${sessionKey2})`);
              const modified = replaceMessageText(msg, emergencyRedacted);
              if (modified) return { message: modified };
            }
          }
        } catch {
        }
      }
    }
  });
  api.on("before_message_write", (event, ctx) => {
    try {
      const sessionKey2 = ctx.sessionKey ?? "";
      if (!sessionKey2) return;
      const msg = event.message;
      if (!msg) return;
      const role = msg.role ?? "";
      const pending = getPendingDetection(sessionKey2);
      const needsDualHistory = isSessionMarkedPrivate(sessionKey2) || pending?.level === "S3" || isActiveLocalRouting(sessionKey2);
      if (needsDualHistory && role !== "tool") {
        const sessionManager = getDefaultSessionManager();
        const msgText = extractMessageText(msg);
        const ts = Date.now();
        if (role === "user" && pending && pending.level !== "S1") {
          const original = pending.originalPrompt ?? msgText;
          sessionManager.writeToFull(sessionKey2, {
            role: "user",
            content: original,
            timestamp: ts,
            sessionKey: sessionKey2
          }).catch((err) => {
            console.error("[GuardClaw] Failed to persist user message to full history:", err);
          });
          const cleanContent = pending.level === "S3" ? buildMainSessionPlaceholder("S3") : pending.desensitized ?? msgText;
          sessionManager.writeToClean(sessionKey2, {
            role: "user",
            content: cleanContent,
            timestamp: ts,
            sessionKey: sessionKey2
          }).catch((err) => {
            console.error("[GuardClaw] Failed to persist user message to clean history:", err);
          });
        } else if (msgText) {
          if (role === "assistant" && isActiveLocalRouting(sessionKey2)) {
            const redacted = redactForCleanTranscript(msgText, getLiveConfig().redaction);
            sessionManager.writeToFull(sessionKey2, {
              role: "assistant",
              content: msgText,
              timestamp: ts,
              sessionKey: sessionKey2
            }).catch((err) => {
              console.error("[GuardClaw] Failed to persist assistant message to full history:", err);
            });
            sessionManager.writeToClean(sessionKey2, {
              role: "assistant",
              content: redacted,
              timestamp: ts,
              sessionKey: sessionKey2
            }).catch((err) => {
              console.error("[GuardClaw] Failed to persist assistant message to clean history:", err);
            });
          } else {
            sessionManager.persistMessage(sessionKey2, {
              role: role || "assistant",
              content: msgText,
              timestamp: ts,
              sessionKey: sessionKey2
            }).catch((err) => {
              console.error("[GuardClaw] Failed to persist message to dual history:", err);
            });
          }
        }
      }
      if (role === "assistant" && isVerifiedGuardSession(sessionKey2)) {
        const assistantText = extractMessageText(msg);
        if (assistantText && assistantText.length >= 4) {
          const secretRedacted = redactTrackedSecrets(sessionKey2, assistantText);
          const fullyRedacted = redactSensitiveInfo(secretRedacted, getLiveConfig().redaction);
          if (fullyRedacted !== assistantText) {
            gcDebug(api.logger, "[GuardClaw] Redacted secrets/PII from guard session assistant response");
            return { message: { ...msg, content: [{ type: "text", text: fullyRedacted }] } };
          }
        }
        return;
      }
      if (role === "assistant" && isActiveLocalRouting(sessionKey2)) {
        const assistantText = extractMessageText(msg);
        if (assistantText && assistantText.length >= 10) {
          const redacted = redactForCleanTranscript(assistantText, getLiveConfig().redaction);
          if (redacted !== assistantText) {
            gcDebug(api.logger, "[GuardClaw] PII-redacted local model response before transcript write");
            return { message: { ...msg, content: [{ type: "text", text: redacted }] } };
          }
        }
      }
      if (role === "assistant" && !isVerifiedGuardSession(sessionKey2) && !isActiveLocalRouting(sessionKey2)) {
        const scanCfg = getLiveConfig().responseScanning;
        if (scanCfg?.enabled) {
          const assistantText = extractMessageText(msg);
          if (assistantText && assistantText.length >= 20) {
            const result = scanResponse(assistantText, scanCfg);
            if (result.hit) {
              api.logger.warn(`[GuardClaw] Response scan hit: ${result.reason} (session=${sessionKey2})`);
              fireWebhooks("response_scan_hit", { sessionKey: sessionKey2, reason: result.reason, details: { matches: result.matches.join(", ") } }, getLiveConfig().webhooks ?? []);
              if (result.action === "block") {
                return { message: { ...msg, content: [{ type: "text", text: "[GuardClaw: Response blocked \u2014 contained sensitive content. Use a local model session to work with sensitive data.]" }] } };
              }
              if (result.action === "redact" && result.redacted !== void 0) {
                gcDebug(api.logger, `[GuardClaw] Response scan: redacted ${result.matches.join(", ")} from cloud response`);
                return { message: { ...msg, content: [{ type: "text", text: result.redacted }] } };
              }
            }
          }
        }
      }
      if (role !== "user") return;
      if (!pending || pending.level === "S1") return;
      if (pending.level === "S3") {
        consumeDetection(sessionKey2);
        return { message: { ...msg, content: [{ type: "text", text: buildMainSessionPlaceholder("S3") }] } };
      }
      if (pending.level === "S2" && pending.desensitized) {
        consumeDetection(sessionKey2);
        return { message: { ...msg, content: [{ type: "text", text: pending.desensitized }] } };
      }
    } catch (err) {
      if (sessionKey) {
        try {
          consumeDetection(sessionKey);
        } catch {
        }
      }
      api.logger.error(`[GuardClaw] Error in before_message_write hook: ${String(err)}`);
    }
  });
  api.on("session_end", async (event, ctx) => {
    const sessionKey2 = event.sessionKey ?? ctx.sessionKey;
    try {
      if (!sessionKey2) return;
      await awaitPendingMemoryWrites(sessionKey2, api.logger);
      const wasPrivate = isSessionMarkedPrivate(sessionKey2);
      api.logger.info(`[GuardClaw] ${wasPrivate ? "private" : "cloud"} session ${sessionKey2} ended.`);
      const memMgr = getDefaultMemoryManager();
      const privacyConfig = getLiveConfig();
      if (isPrimaryModelCloud(api)) {
        api.logger.info("[GuardClaw] Skipping FULL\u2192CLEAN memory sync \u2014 primary model is cloud (PII safety)");
      } else {
        await memMgr.syncAllMemoryToClean(privacyConfig);
      }
      const collector = getGlobalCollector();
      if (collector) await collector.flush();
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in session_end hook: ${String(err)}`);
    } finally {
      if (sessionKey2) {
        try {
          clearSessionState(sessionKey2);
        } catch {
        }
        try {
          clearSessionSecrets(sessionKey2);
        } catch {
        }
        try {
          clearBehavioralSession(sessionKey2);
        } catch {
        }
        try {
          deregisterGuardSession(sessionKey2);
        } catch {
        }
      }
    }
  });
  api.on("after_compaction", async (_event, ctx) => {
    try {
      if (ctx.workspaceDir) _cachedWorkspaceDir = ctx.workspaceDir;
      if (isPrimaryModelCloud(api)) {
        gcDebug(api.logger, "[GuardClaw] Skipping memory sync after compaction \u2014 primary model is cloud");
      } else {
        const memMgr = getDefaultMemoryManager();
        const privacyConfig = getLiveConfig();
        await memMgr.syncAllMemoryToClean(privacyConfig);
        gcDebug(api.logger, "[GuardClaw] Memory synced after compaction");
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in after_compaction hook: ${String(err)}`);
    }
  });
  api.on("llm_output", async (event, ctx) => {
    try {
      const sessionKey2 = ctx.sessionKey ?? event.sessionId ?? "";
      const provider = event.provider ?? "unknown";
      const model = event.model ?? "unknown";
      const collector = getGlobalCollector();
      collector?.record({
        sessionKey: sessionKey2,
        provider,
        model,
        source: "task",
        usage: event.usage
      });
      const liveConfig = getLiveConfig();
      const budgetCfg = liveConfig.budget;
      if (budgetCfg?.enabled && event.usage) {
        const cost = calculateCost(model, { input: event.usage.input, output: event.usage.output }, liveConfig.modelPricing ?? {});
        if (cost > 0) {
          recordCost(cost);
          const status = checkBudget(budgetCfg);
          if (status.warning && !status.exceeded) {
            const msg = `Budget at ${Math.round(status.dailyCost / (status.dailyCap ?? Infinity) * 100)}% daily / ${Math.round(status.monthlyCost / (status.monthlyCap ?? Infinity) * 100)}% monthly`;
            fireWebhooks("budget_warning", { sessionKey: sessionKey2, reason: msg, details: { dailyCost: status.dailyCost, monthlyCost: status.monthlyCost } }, liveConfig.webhooks ?? []);
          }
        }
      }
      const origin = provider === "guardclaw-privacy" ? "cloud" : isLocalProvider(provider, liveConfig.localProviders) ? "local" : "cloud";
      const reason = provider === "guardclaw-privacy" ? "guardclaw_proxy_to_cloud" : origin === "local" ? "local_provider" : "provider_not_local";
      recordFinalReply({
        sessionKey: sessionKey2,
        provider,
        model,
        usage: event.usage,
        extraLocalProviders: liveConfig.localProviders,
        originHint: origin,
        reasonHint: reason
      });
      finalizeLoop(sessionKey2);
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in llm_output hook: ${String(err)}`);
    }
  });
  api.on("before_reset", async (_event, ctx) => {
    try {
      if (ctx.workspaceDir) _cachedWorkspaceDir = ctx.workspaceDir;
      const sessionKey2 = ctx.sessionKey ?? "";
      if (sessionKey2) await awaitPendingMemoryWrites(sessionKey2, api.logger);
      if (isPrimaryModelCloud(api)) {
        gcDebug(api.logger, "[GuardClaw] Skipping memory sync before reset \u2014 primary model is cloud");
      } else {
        const memMgr = getDefaultMemoryManager();
        const privacyConfig = getLiveConfig();
        await memMgr.syncAllMemoryToClean(privacyConfig);
        gcDebug(api.logger, "[GuardClaw] Memory synced before reset");
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_reset hook: ${String(err)}`);
    }
  });
  api.on("message_sending", async (event, ctx) => {
    try {
      const { content, to } = event;
      if (!content?.trim()) return;
      const privacyConfig = getLiveConfig();
      if (!privacyConfig.enabled) return;
      const sessionKey2 = ctx.sessionKey ?? "";
      if (isActiveLocalRouting(sessionKey2)) {
        gcDebug(api.logger, `[GuardClaw] Local routing active \u2014 skipping outbound redaction (session=${sessionKey2})`);
        return;
      }
      if (isSessionMarkedPrivate(sessionKey2) && (privacyConfig.s2Policy ?? "proxy") === "local") {
        gcDebug(api.logger, `[GuardClaw] S2-local session \u2014 skipping outbound redaction (session=${sessionKey2})`);
        return;
      }
      if (!isPrimaryModelCloud(api)) {
        gcDebug(api.logger, `[GuardClaw] Primary model is local \u2014 skipping outbound redaction (session=${sessionKey2})`);
        return;
      }
      const explicitOperators = privacyConfig.operatorPassthrough ?? [];
      if (explicitOperators.length > 0 && to && explicitOperators.includes(to)) {
        api.logger.info(`[GuardClaw] Operator passthrough \u2014 skipping redaction for trusted recipient: ${to}`);
        return;
      }
      if (to && (to.startsWith("channel:") || to.startsWith("#") || to === "channel")) {
        api.logger.info(`[GuardClaw] Channel message \u2014 skipping outbound redaction for: ${to}`);
        return;
      }
      const pipeline = getGlobalPipeline();
      if (!pipeline) return;
      let outboundContent = content;
      const secretRedacted = redactTrackedSecrets(sessionKey2, outboundContent);
      if (secretRedacted !== outboundContent) {
        api.logger.warn(`[GuardClaw] Redacted tracked secret(s) from outbound message (session=${sessionKey2})`);
        outboundContent = secretRedacted;
      }
      const decision = await pipeline.run(
        "onUserMessage",
        { checkpoint: "onUserMessage", message: outboundContent, sessionKey: sessionKey2 },
        getPipelineConfig()
      );
      if (decision.level === "S3" || decision.action === "block") {
        api.logger.warn("[GuardClaw] BLOCKED outbound message: S3/block detected");
        return { cancel: true };
      }
      if (decision.level === "S2") {
        const desenResult = await desensitizeWithLocalModel(outboundContent, privacyConfig, ctx.sessionKey);
        if (desenResult.failed) {
          api.logger.warn("[GuardClaw] S2 desensitization failed \u2014 cancelling outbound message to prevent PII leak");
          return { cancel: true };
        }
        return { content: desenResult.desensitized };
      }
      if (outboundContent !== content) return { content: outboundContent };
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in message_sending hook: ${String(err)}`);
    }
  });
  api.on("before_agent_start", async (event, ctx) => {
    try {
      const { prompt } = event;
      const sessionKey2 = ctx.sessionKey ?? "";
      if (!sessionKey2.includes(":subagent:") || !prompt?.trim()) return;
      const privacyConfig = getLiveConfig();
      if (!privacyConfig.enabled) return;
      const pipeline = getGlobalPipeline();
      if (!pipeline) return;
      const decision = await pipeline.run(
        "onUserMessage",
        { checkpoint: "onUserMessage", message: prompt, sessionKey: sessionKey2, agentId: ctx.agentId },
        getPipelineConfig()
      );
      if (decision.level === "S3" || decision.action === "block") {
        const guardCfg = getGuardAgentConfig(privacyConfig);
        const defaultProvider = privacyConfig.localModel?.provider ?? "ollama";
        const provider = guardCfg?.provider ?? defaultProvider;
        api.logger.info(`[GuardClaw] Subagent ${decision.level} \u2014 routing to ${provider}${guardCfg?.modelName ? "/" + guardCfg.modelName : ""}`);
        return {
          providerOverride: provider,
          ...guardCfg?.modelName ? { modelOverride: guardCfg.modelName } : {}
        };
      }
      if (decision.level === "S2") {
        const privacyCfg = getLiveConfig();
        const desenResult = await desensitizeWithLocalModel(prompt, privacyCfg, sessionKey2);
        if (desenResult.failed) {
          const guardCfg = getGuardAgentConfig(privacyCfg);
          const fallbackProvider = privacyCfg.localModel?.provider ?? "ollama";
          const provider = guardCfg?.provider ?? fallbackProvider;
          api.logger.warn(`[GuardClaw] Subagent S2 desensitization failed \u2014 routing to local ${provider}${guardCfg?.modelName ? "/" + guardCfg.modelName : ""}`);
          return { providerOverride: provider, ...guardCfg?.modelName ? { modelOverride: guardCfg.modelName } : {} };
        }
        api.logger.info("[GuardClaw] Subagent S2 \u2014 prompt desensitized before forwarding");
        return { prompt: desenResult.desensitized };
      }
    } catch (err) {
      api.logger.error(`[GuardClaw] Error in before_agent_start hook: ${String(err)}`);
    }
  });
  api.on("message_received", async (event, ctx) => {
    try {
      const privacyConfig = getLiveConfig();
      if (!privacyConfig.enabled) return;
      api.logger.info?.(`[GuardClaw] Message received from ${event.from ?? "unknown"}`);
      const msgText = String(event.message ?? event.content ?? "");
      const envelopeMatch = msgText.match(/"sender_id"\s*:\s*"(\d+)"/);
      const senderId = envelopeMatch?.[1] ?? event.metadata?.senderId ?? (typeof event.from === "string" && /^\d+$/.test(event.from) ? event.from : void 0);
      if (senderId && ctx.channelId) {
        setLastSenderId(ctx.channelId, senderId);
        api.logger.debug?.(`[GuardClaw S0] Stashed senderId=${senderId} for channel=${ctx.channelId}`);
      }
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
var GUARD_BASH_NETWORK_PATTERNS = [
  { pattern: /\bcurl\b/i, tool: "curl" },
  { pattern: /\bwget\b/i, tool: "wget" },
  { pattern: /(?:^|\s)ncat?\b/m, tool: "nc/ncat" },
  { pattern: /\bnetcat\b/i, tool: "netcat" },
  { pattern: /\bsocat\b/i, tool: "socat" },
  { pattern: /\bssh\s/i, tool: "ssh" },
  { pattern: /\bscp\s/i, tool: "scp" },
  { pattern: /\bsftp\s/i, tool: "sftp" },
  { pattern: /\brsync\s+\S*@/i, tool: "rsync (remote)" },
  { pattern: /\bftp\s/i, tool: "ftp" },
  { pattern: /\btelnet\b/i, tool: "telnet" },
  { pattern: /\bopenssl\s+s_client\b/i, tool: "openssl s_client" },
  { pattern: /\/dev\/tcp\//, tool: "/dev/tcp" },
  { pattern: /\bpython[23]?\b[\s\S]*?-c[\s\S]*?socket/i, tool: "python socket" },
  { pattern: /\bnode\b[\s\S]*?-e[\s\S]*?(?:http|https|net|tls)\b/i, tool: "node net" },
  { pattern: /\bperl\b[\s\S]*?-e[\s\S]*?socket/i, tool: "perl socket" },
  // GCF-015: Cloud CLI tools — each can exfiltrate files to attacker-controlled storage
  { pattern: /\baws\s/i, tool: "aws-cli" },
  { pattern: /\bgsutil\s/i, tool: "gsutil" },
  { pattern: /\baz\s/i, tool: "azure-cli" },
  { pattern: /\bdocker\s+push\b/i, tool: "docker push" },
  // git push with a remote URL (not just 'git push origin' — but catch URL forms)
  { pattern: /\bgit\s+(?:push|remote\s+add)\s+(?:\S+\s+)?https?:\/\//i, tool: "git push (url)" },
  // Scripting language one-liners that make network calls
  { pattern: /\bruby\s+-e\b/i, tool: "ruby -e" },
  { pattern: /\bphp\s+-r\b/i, tool: "php -r" },
  // DNS exfiltration via nslookup/dig
  { pattern: /\bnslookup\b/i, tool: "nslookup" },
  { pattern: /\bdig\s/i, tool: "dig" },
  // GCF-016: Obfuscation primitives — block entirely to prevent bypass of all above patterns
  { pattern: /\beval\b/i, tool: "eval (obfuscation)" },
  { pattern: /\bexec\b/i, tool: "exec (obfuscation)" },
  { pattern: /\bsource\b/i, tool: "source (obfuscation)" },
  { pattern: /\b\.\s+[^\s]/, tool: "source-dot (obfuscation)" }
];
function isGuardNetworkCommand(command) {
  for (const { pattern, tool } of GUARD_BASH_NETWORK_PATTERNS) {
    if (pattern.test(command)) return tool;
  }
  return null;
}
var TOOL_NOISE_PATTERNS = /^\s*(?:[\u2713\u2714\u2715\u2716\u2022\u25cf\u25cb•·\-\*]\s*)?(?:ok|done|success|created|updated|deleted|wrote|saved|started|stopped|finished|completed|running|exited?\s*(?:code\s*)?\d*|true|false|null|undefined|\d+(?:\.\d+)?\s*(?:ms|s|sec|bytes?|[kmg]b)?|no\s+(?:results?|matches?|changes?|output)|\[\d+\/\d+\]|\d+\s+files?|empty|skipped|unchanged|passed|failed|error|warning|\{\}|\[\]|\s*)$/i;
var TOOL_NOISE_TOOL_NAMES = /* @__PURE__ */ new Set([
  "list_dir",
  "list_directory",
  "ls",
  "search_files",
  "find_files",
  "task_status",
  "task_progress",
  "get_status",
  "ping",
  "health_check",
  "list_sessions",
  "list_agents"
]);
var SENSITIVE_WORDS_RE = /\b(?:password|passphrase|passwd|secret|token|credential|api.?key|private.?key|auth|ssn|salary|payroll|diagnosis|diagnos|patient|medical|prescription|bank|account|routing|bsb|acn|abn|tfn|medicare|ssn|license|passport|encrypt|decrypt)\b/i;
function isToolNoise(text, toolName) {
  const trimmed = text.trim();
  if (!trimmed) return true;
  if (toolName && TOOL_NOISE_TOOL_NAMES.has(toolName)) return true;
  if (TOOL_NOISE_PATTERNS.test(trimmed)) return true;
  if (!trimmed.includes("\n") && trimmed.length < 80 && !/[@\d]{4,}|\b\d{3}[-.]\d{3}/.test(trimmed) && !SENSITIVE_WORDS_RE.test(trimmed)) return true;
  return false;
}
function shouldSkipMessage(msg) {
  if (msg.includes("[REDACTED:") || msg.startsWith("[SYSTEM]")) return true;
  if (/^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}/.test(msg)) return true;
  if (msg.includes("<<<EXTERNAL_UNTRUSTED_CONTENT") && msg.includes("Untrusted channel metadata") && !extractUserContent(msg)) return true;
  return false;
}
function stripThreadContextPrefix(msg) {
  if (!msg.startsWith("[Thread starter")) return msg;
  const lastBlockEnd = msg.lastIndexOf("```\n\n");
  if (lastBlockEnd !== -1) {
    const after = msg.slice(lastBlockEnd + 5).trim();
    if (after.length > 0) return after;
  }
  const match = msg.match(/```\s*\n+([\s\S]+)$/);
  if (match?.[1]?.trim()) return match[1].trim();
  return msg;
}
function extractUserContent(msg) {
  if (!msg.includes("conversation_label") && !msg.includes("sender_id")) {
    return msg;
  }
  const lastJsonBlockEnd = msg.lastIndexOf("```\n\n");
  if (lastJsonBlockEnd !== -1) {
    const afterBlock = msg.slice(lastJsonBlockEnd + 5).trim();
    if (afterBlock.length > 0) return afterBlock;
  }
  const senderBlockMatch = msg.match(/```\s*\n\s*\n([^`]+)$/);
  if (senderBlockMatch && senderBlockMatch[1].trim()) {
    return senderBlockMatch[1].trim();
  }
  const paragraphs = msg.split(/\n\n+/);
  for (let i = paragraphs.length - 1; i >= 0; i--) {
    const p = paragraphs[i].trim();
    if (p.startsWith("```") || p.startsWith("{") || p.startsWith("[Thread") || p.includes("conversation_label") || p.includes("sender_id") || p.startsWith("Conversation info") || p.startsWith("Sender")) {
      continue;
    }
    if (p.length > 0) return p;
  }
  return "";
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
async function loadDualTrackContext(sessionKey2, agentId, limit) {
  try {
    const mgr = getDefaultSessionManager();
    const delta = await mgr.loadHistoryDelta(sessionKey2, agentId ?? "main", limit);
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
    content = await fs4.promises.readFile(absPath, "utf-8");
  } catch {
    return;
  }
  if (!content.trim()) return;
  try {
    const srcStat = await fs4.promises.lstat(absPath);
    if (srcStat.isSymbolicLink()) {
      logger.warn(`[GuardClaw] Memory dual-write blocked \u2014 source path is a symlink: ${absPath}`);
      return;
    }
  } catch {
  }
  let fullRelPath;
  if (rel === "MEMORY.md" || rel === "memory.md") {
    fullRelPath = "MEMORY-FULL.md";
  } else if (rel.startsWith("memory/")) {
    fullRelPath = rel.replace(/^memory\//, "memory-full/");
  } else {
    return;
  }
  const fullAbsPath = path3.resolve(workspaceDir, fullRelPath);
  await fs4.promises.mkdir(path3.dirname(fullAbsPath), { recursive: true });
  try {
    const dstStat = await fs4.promises.lstat(fullAbsPath);
    if (dstStat.isSymbolicLink()) {
      logger.warn(`[GuardClaw] Memory dual-write blocked \u2014 destination path is a symlink: ${fullAbsPath}`);
      return;
    }
  } catch {
  }
  const fullContent = isGuardSession ? `${GUARD_SECTION_BEGIN}
${content}
${GUARD_SECTION_END}` : content;
  await fs4.promises.writeFile(fullAbsPath, fullContent, { encoding: "utf-8", mode: 384 });
  const memMgr = getDefaultMemoryManager();
  const redacted = await memMgr.redactContentPublic(content, privacyConfig);
  if (redacted !== content) {
    await fs4.promises.writeFile(absPath, redacted, { encoding: "utf-8", mode: 384 });
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
      const isHighConfidenceRuleHit = detector === "ruleDetector" && (result.confidence ?? 0) >= 1;
      if (result.level === "S3" || result.level === "S2" && isHighConfidenceRuleHit) {
        if (isHighConfidenceRuleHit && result.level === "S2") {
          console.debug(`[GuardClaw] Short-circuit: rule engine S2 hit (${result.reason}) \u2014 skipping LLM`);
        }
        break;
      }
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
    return {
      level: "S3",
      action: "redirect",
      ...guardCfg ? {
        target: {
          provider: guardCfg.provider,
          ...guardCfg.modelName ? { model: guardCfg.modelName } : {}
        }
      } : {},
      reason
    };
  }
  const s2Policy = privacyConfig.s2Policy ?? "proxy";
  if (s2Policy === "local") {
    const guardCfg = getGuardAgentConfig(privacyConfig);
    return {
      level: "S2",
      action: "redirect",
      ...guardCfg ? {
        target: {
          provider: guardCfg.provider,
          ...guardCfg.modelName ? { model: guardCfg.modelName } : {}
        }
      } : {},
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
var OPENROUTER_PROVIDER = "openrouter";
var OPENROUTER_DEFAULT_MODEL = "auto";
var DEFAULT_CONFIG2 = {
  enabled: false,
  judgeEndpoint: "http://localhost:11434",
  judgeModel: DEFAULT_LOCAL_CLASSIFIER_MODEL,
  judgeProviderType: "openai-compatible",
  tiers: {
    SIMPLE: { provider: "openai", model: "gpt-4o-mini" },
    MEDIUM: { provider: "openai", model: "gpt-4o" },
    COMPLEX: { provider: "anthropic", model: "claude-sonnet-4.6" },
    REASONING: { provider: "openai", model: "o4-mini" }
  },
  cacheTtlMs: 3e5
};
var OPENROUTER_DEFAULT_TIERS = {
  SIMPLE: { provider: OPENROUTER_PROVIDER, model: "openai/gpt-4o-mini" },
  MEDIUM: { provider: OPENROUTER_PROVIDER, model: "openai/gpt-4o" },
  COMPLEX: { provider: OPENROUTER_PROVIDER, model: "anthropic/claude-sonnet-4.6" },
  REASONING: { provider: OPENROUTER_PROVIDER, model: "openai/o4-mini" }
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
function resolveConfig2(pluginConfig) {
  const routers = pluginConfig?.privacy?.routers;
  const tsConfig = routers?.["token-saver"];
  const options = tsConfig?.options ?? {};
  const privacyLocalModel = pluginConfig?.privacy?.localModel;
  const orCfg = options.openrouter ?? {};
  const openrouterEnabled = orCfg.enabled === true;
  const orProviderName = orCfg.providerName ?? OPENROUTER_PROVIDER;
  const baseTiers = openrouterEnabled && !orCfg.passthrough ? Object.fromEntries(
    Object.entries(OPENROUTER_DEFAULT_TIERS).map(([k, v]) => [k, { ...v, provider: orProviderName }])
  ) : DEFAULT_CONFIG2.tiers;
  return {
    enabled: tsConfig?.enabled ?? DEFAULT_CONFIG2.enabled,
    judgeEndpoint: options.judgeEndpoint ?? privacyLocalModel?.endpoint ?? DEFAULT_CONFIG2.judgeEndpoint,
    judgeModel: options.judgeModel ?? privacyLocalModel?.model ?? DEFAULT_CONFIG2.judgeModel,
    judgeProviderType: options.judgeProviderType ?? privacyLocalModel?.type ?? DEFAULT_CONFIG2.judgeProviderType,
    judgeCustomModule: options.judgeCustomModule ?? privacyLocalModel?.module,
    judgeApiKey: options.judgeApiKey ?? privacyLocalModel?.apiKey,
    tiers: {
      ...baseTiers,
      ...options.tiers ?? {}
    },
    cacheTtlMs: options.cacheTtlMs ?? DEFAULT_CONFIG2.cacheTtlMs,
    openrouter: openrouterEnabled ? {
      enabled: true,
      passthrough: orCfg.passthrough === true,
      providerName: orProviderName,
      model: orCfg.model ?? OPENROUTER_DEFAULT_MODEL
    } : void 0
  };
}
var tokenSaverRouter = {
  id: "token-saver",
  async detect(context, pluginConfig) {
    const config = resolveConfig2(pluginConfig);
    if (!config.enabled && !context.dryRun) {
      return { level: "S1", action: "passthrough" };
    }
    const isSubagent = context.sessionKey?.includes(":subagent:") ?? false;
    if (isSubagent) {
      return { level: "S1", action: "passthrough", reason: "subagent \u2014 skipped" };
    }
    if (config.openrouter?.enabled && config.openrouter.passthrough) {
      return {
        level: "S1",
        action: "redirect",
        target: {
          provider: config.openrouter.providerName ?? OPENROUTER_PROVIDER,
          model: config.openrouter.model ?? OPENROUTER_DEFAULT_MODEL
        },
        reason: "openrouter passthrough",
        confidence: 1
      };
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
import { join as join11 } from "path";

// src/presets.ts
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { join as join9 } from "path";
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
var OPENCLAW_DIR = join9(process.env.HOME ?? "/tmp", ".openclaw");
var GUARDCLAW_CONFIG_PATH = join9(OPENCLAW_DIR, "guardclaw.json");
var OPENCLAW_CONFIG_PATH = join9(OPENCLAW_DIR, "openclaw.json");
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
    writeFileSync(GUARDCLAW_CONFIG_PATH, JSON.stringify(config, null, 2), { encoding: "utf-8", mode: 384 });
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
    writeFileSync(OPENCLAW_CONFIG_PATH, JSON.stringify(config, null, 2), { encoding: "utf-8", mode: 384 });
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
var MAX_PATTERN_LENGTH = 500;
function checkPatterns2(text, patterns) {
  for (const pat of patterns.S3 ?? []) {
    if (pat.length > MAX_PATTERN_LENGTH) {
      console.warn(`[GuardClaw] S3 pattern too long (>${MAX_PATTERN_LENGTH} chars), skipped`);
      continue;
    }
    try {
      if (new RegExp(pat, "i").test(text)) {
        return { level: "S3", reason: `S3 pattern: ${pat}` };
      }
    } catch (e) {
      console.warn(`[GuardClaw] Invalid S3 regex pattern skipped: ${String(e)}`);
    }
  }
  for (const pat of patterns.S2 ?? []) {
    if (pat.length > MAX_PATTERN_LENGTH) {
      console.warn(`[GuardClaw] S2 pattern too long (>${MAX_PATTERN_LENGTH} chars), skipped`);
      continue;
    }
    try {
      if (new RegExp(pat, "i").test(text)) {
        return { level: "S2", reason: `S2 pattern: ${pat}` };
      }
    } catch (e) {
      console.warn(`[GuardClaw] Invalid S2 regex pattern skipped: ${String(e)}`);
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
  } catch (err) {
    console.warn(`[GuardClaw] Configurable router LLM classification failed:`, String(err));
    return null;
  }
}
function resolveTargetForLevel(level, pluginConfig) {
  const pCfg = getPrivacyConfig2(pluginConfig);
  if (level === "S3") {
    const guardCfg = getGuardAgentConfig(pCfg);
    if (!guardCfg) return null;
    return {
      provider: guardCfg.provider,
      ...guardCfg.modelName ? { model: guardCfg.modelName } : {}
    };
  }
  const s2Policy = pCfg.s2Policy ?? "proxy";
  if (s2Policy === "local") {
    const guardCfg = getGuardAgentConfig(pCfg);
    if (!guardCfg) return null;
    return {
      provider: guardCfg.provider,
      ...guardCfg.modelName ? { model: guardCfg.modelName } : {}
    };
  }
  return { provider: "guardclaw-privacy" };
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
        target = resolveTargetForLevel(finalLevel, pluginConfig) ?? void 0;
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

// src/model-advisor.ts
import { readFile as readFile4, writeFile as writeFile3, rename as rename3, statfs } from "fs/promises";
import { execFile as execFile3 } from "child_process";
import { promisify as promisify3 } from "util";
import { join as join10 } from "path";
import { createHash as createHash2 } from "crypto";
var execFileAsync3 = promisify3(execFile3);
var HOME4 = process.env.HOME ?? process.env.USERPROFILE ?? "/tmp";
var SUGGESTIONS_PATH = join10(HOME4, ".openclaw", "guardclaw-suggestions.json");
var MS_PER_WEEK = 7 * 24 * 60 * 60 * 1e3;
var OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models";
var HF_PROTECTAI_URL = "https://huggingface.co/api/models?author=protectai&search=prompt-injection";
var CURRENT_DEBERTA_MODEL = "protectai/deberta-v3-base-prompt-injection-v2";
var CURRENT_DEBERTA_VERSION = 2;
var FETCH_TIMEOUT_MS = 15e3;
var REASONING_KEYWORDS = ["thinking", "reasoning", "qwq", "deepseek-r1", "o1", "o3", "r1-", "r1:"];
var COMPLEX_KEYWORDS = ["opus", "sonnet", "large", "pro", "plus", "70b", "72b", "34b", "65b", "gemini-2.5"];
var SMALL_KEYWORDS = ["mini", "haiku", "flash", "lite", "nano", "small", "tiny", "3b", "1b", "0.5b"];
var BENCHMARK_PROMPTS = [
  { prompt: "What is the capital of France?", expectedTier: "SIMPLE" },
  { prompt: "Write a Python function that returns the Fibonacci sequence up to n.", expectedTier: "MEDIUM" },
  { prompt: "Design a microservices architecture for a hospital management system with departments, doctors, patients, appointments, and billing. Describe the key services and their interactions.", expectedTier: "COMPLEX" },
  { prompt: "Prove by mathematical induction that the sum of the first n natural numbers equals n(n+1)/2.", expectedTier: "REASONING" }
];
var _data2 = { lastCheckedAt: null, suggestions: [] };
var _config = {};
var _openrouterApiKey = "";
var _logger = console;
var _scheduleTimer = null;
var _running = false;
async function loadAdvisorData() {
  try {
    const raw = await readFile4(SUGGESTIONS_PATH, "utf-8");
    _data2 = JSON.parse(raw);
    const cutoff = Date.now() - 60 * 24 * 60 * 60 * 1e3;
    _data2.suggestions = _data2.suggestions.filter(
      (s) => s.status === "pending" || new Date(s.createdAt).getTime() > cutoff
    );
  } catch {
  }
}
async function saveAdvisorData() {
  const tmp = SUGGESTIONS_PATH + ".tmp";
  try {
    await writeFile3(tmp, JSON.stringify(_data2, null, 2), { encoding: "utf-8", mode: 384 });
    await rename3(tmp, SUGGESTIONS_PATH);
  } catch {
  }
}
function makeSuggestionId(type, value) {
  return createHash2("sha256").update(`${type}:${value}`).digest("hex").slice(0, 12);
}
function hasSuggestion(id) {
  return _data2.suggestions.some((s) => s.id === id && s.status === "pending");
}
async function getFreeDiskGb(checkPath) {
  const paths = [
    checkPath,
    process.env.OLLAMA_MODELS,
    join10(HOME4, ".ollama"),
    HOME4
  ].filter(Boolean);
  for (const p of paths) {
    try {
      const stats = await statfs(p);
      return stats.bfree * stats.bsize / 1024 ** 3;
    } catch {
    }
  }
  return 999;
}
function blendedCostPer1M(pricing) {
  const input = parseFloat(pricing.prompt) * 1e6;
  const output = parseFloat(pricing.completion) * 1e6;
  if (isNaN(input) || isNaN(output)) return Infinity;
  return (input + output) / 2;
}
function isTierCompatible(model, tier) {
  const id = model.id.toLowerCase();
  const name = (model.name ?? "").toLowerCase();
  const text = `${id} ${name}`;
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
      return isReasoning && !isSmall;
  }
}
async function checkOpenRouterModels(minSavingsPct) {
  const apiKey = _openrouterApiKey || _config.openrouterApiKey;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let models = [];
  try {
    const headers = {};
    if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
    const res = await fetch(OPENROUTER_MODELS_URL, {
      headers,
      signal: controller.signal
    });
    clearTimeout(timer);
    if (!res.ok) {
      _logger.warn(`[GuardClaw Advisor] OpenRouter models API returned ${res.status}`);
      return [];
    }
    const body = await res.json();
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
  function normalizeVersionId(id) {
    return id.replace(/-(\d+)$/, ".$1");
  }
  const byId = new Map(models.map((m) => [m.id, m]));
  const byNormalizedId = new Map(models.map((m) => [normalizeVersionId(m.id), m]));
  const privacy = getLiveConfig();
  const routers = privacy.routers;
  const tsOptions = routers?.["token-saver"]?.options ?? {};
  const currentTiers = tsOptions.tiers ?? {};
  const DEFAULT_TIERS = {
    SIMPLE: { provider: "openrouter", model: "openai/gpt-4o-mini" },
    MEDIUM: { provider: "openrouter", model: "openai/gpt-4o" },
    COMPLEX: { provider: "anthropic", model: "claude-sonnet-4.6" },
    REASONING: { provider: "openai", model: "o4-mini" }
  };
  const tiers = { ...DEFAULT_TIERS, ...currentTiers };
  const suggestions = [];
  for (const [tier, target] of Object.entries(tiers)) {
    const currentId = target.model.includes("/") ? target.model : `${target.provider}/${target.model}`;
    const currentModel = byId.get(currentId) ?? byNormalizedId.get(normalizeVersionId(currentId));
    const currentCost = currentModel ? blendedCostPer1M(currentModel.pricing) : Infinity;
    if (currentCost === Infinity) continue;
    let cheapest = null;
    let bestValue = null;
    let bestModel = null;
    for (const model of models) {
      if (model.id === currentId) continue;
      if (!isTierCompatible(model, tier)) continue;
      const cost = blendedCostPer1M(model.pricing);
      const savings = (currentCost - cost) / currentCost * 100;
      if (savings >= minSavingsPct) {
        if (!cheapest || cost < cheapest.cost) cheapest = { model, cost, savings };
      }
      if (cost < currentCost) {
        const ctx = Math.min(model.context_length ?? 4096, 2e5);
        const valueScore = ctx / cost;
        if (!bestValue || valueScore > bestValue.valueScore) {
          bestValue = { model, cost, savings, valueScore };
        }
      }
      if (cost <= currentCost * 3) {
        if (!bestModel || cost > bestModel.cost) bestModel = { model, cost, savings };
      }
    }
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const seen = /* @__PURE__ */ new Set();
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
            contextLength: cheapest.model.context_length
          }
        });
      }
    }
    if (bestValue && !seen.has(bestValue.model.id)) {
      const id = makeSuggestionId("openrouter_best_value", `${tier}:${bestValue.model.id}`);
      if (!hasSuggestion(id)) {
        seen.add(bestValue.model.id);
        const ctxK = ((bestValue.model.context_length ?? 0) / 1e3).toFixed(0);
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
            contextLength: bestValue.model.context_length
          }
        });
      }
    }
    if (bestModel && !seen.has(bestModel.model.id)) {
      const id = makeSuggestionId("openrouter_best", `${tier}:${bestModel.model.id}`);
      if (!hasSuggestion(id)) {
        const savingsStr = bestModel.savings > 0 ? `, ${bestModel.savings.toFixed(0)}% cheaper than ${currentId}` : ` (${((bestModel.cost / currentCost - 1) * 100).toFixed(0)}% more than ${currentId})`;
        suggestions.push({
          id,
          type: "openrouter_best",
          status: "pending",
          createdAt: now,
          title: `Top ${tier} model`,
          description: `${bestModel.model.name ?? bestModel.model.id} is the highest-rated available model for ${tier} tasks on OpenRouter${savingsStr}.`,
          currentValue: currentId,
          suggestedValue: bestModel.model.id,
          savingsPercent: bestModel.savings > 0 ? Math.round(bestModel.savings) : void 0,
          details: {
            tier,
            category: "best",
            currentCostPer1M: currentCost.toFixed(4),
            candidateCostPer1M: bestModel.cost.toFixed(4),
            contextLength: bestModel.model.context_length
          }
        });
      }
    }
  }
  _logger.info(`[GuardClaw Advisor] OpenRouter: ${suggestions.length} suggestion(s) after filtering`);
  return suggestions;
}
async function checkLLMFitModels(minDiskGb) {
  try {
    await execFileAsync3("llmfit", ["--version"], { timeout: 5e3 });
  } catch {
    return [];
  }
  let raw;
  try {
    const { stdout } = await execFileAsync3("llmfit", ["recommend", "--json", "--limit", "10"], {
      timeout: 3e4
    });
    raw = stdout;
  } catch (err) {
    _logger.warn(`[GuardClaw Advisor] LLMFit command failed: ${String(err)}`);
    return [];
  }
  let entries = [];
  try {
    const parsed = JSON.parse(raw);
    const arr = Array.isArray(parsed) ? parsed : parsed?.models;
    if (!Array.isArray(arr)) {
      _logger.warn(`[GuardClaw Advisor] LLMFit: unexpected output format`);
      return [];
    }
    _logger.info(`[GuardClaw Advisor] LLMFit: parsed ${arr.length} candidate(s)`);
    entries = arr.map((e) => ({
      name: e.name ?? e.model,
      model: e.model,
      fit: (e.fit ?? e.fit_level)?.toLowerCase(),
      tokens_per_sec: e.tokens_per_sec ?? e.estimated_tps,
      memory_gb: e.memory_gb ?? e.memory_required_gb,
      context_length: e.context_length ?? e.context,
      quantization: e.quantization ?? e.quant,
      rank: e.rank,
      score: e.score,
      category: e.category
    }));
  } catch {
    return [];
  }
  const currentJudge = getLiveConfig().localModel?.model ?? DEFAULT_LOCAL_CLASSIFIER_MODEL;
  const freeDiskGb = await getFreeDiskGb();
  const suggestions = [];
  for (const entry of entries.slice(0, 5)) {
    const modelName = entry.name ?? entry.model;
    if (!modelName) continue;
    if (modelName === currentJudge) continue;
    if (entry.fit && entry.fit !== "perfect" && entry.fit !== "good") continue;
    const tps = entry.tokens_per_sec ?? entry.tps;
    const id = makeSuggestionId("local_model", modelName);
    if (hasSuggestion(id)) continue;
    const estimatedGb = entry.memory_gb ?? (entry.score ? Math.max(2, 10 - entry.score / 15) : 5);
    if (freeDiskGb < minDiskGb) {
      _logger.warn(`[GuardClaw Advisor] Skipping local model suggestion \u2014 only ${freeDiskGb.toFixed(1)} GB free (need ${minDiskGb} GB)`);
      continue;
    }
    suggestions.push({
      id,
      type: "local_model",
      status: "pending",
      createdAt: (/* @__PURE__ */ new Date()).toISOString(),
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
        freeDiskGb: freeDiskGb.toFixed(1)
      }
    });
  }
  return suggestions;
}
async function checkDebertaUpdates() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  let hfModels = [];
  try {
    const res = await fetch(HF_PROTECTAI_URL, { signal: controller.signal });
    clearTimeout(timer);
    if (!res.ok) return [];
    hfModels = await res.json();
    if (!Array.isArray(hfModels)) return [];
  } catch {
    clearTimeout(timer);
    return [];
  }
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
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    title: `Newer injection detection model: v${latestVersion}`,
    description: `${latestId} is available on HuggingFace. Accepting updates the injection config \u2014 the new model is downloaded automatically on next startup.`,
    currentValue: CURRENT_DEBERTA_MODEL,
    suggestedValue: latestId,
    details: { currentVersion: CURRENT_DEBERTA_VERSION, latestVersion }
  }];
}
async function benchmarkModel(endpoint, model, providerType, runs) {
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
          { role: "user", content: prompt }
        ],
        { temperature: 0, maxTokens: 128, providerType }
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
  if (errors === runs) {
    throw new Error(`All ${runs} benchmark calls failed \u2014 model likely unavailable`);
  }
  return {
    jsonSuccessRate: successes / BENCHMARK_PROMPTS.slice(0, runs).length,
    avgLatencyMs: Math.round(totalMs / BENCHMARK_PROMPTS.slice(0, runs).length),
    runs
  };
}
async function runAdvisorChecks() {
  if (_running) return;
  if (!_config.enabled) return;
  _running = true;
  _logger.info("[GuardClaw Advisor] Starting model checks\u2026");
  try {
    const minSavings = _config.minSavingsPercent ?? 20;
    const minDisk = _config.minDiskSpaceGb ?? 10;
    const allNew = [];
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
    if (_config.deberta?.enabled !== false) {
      try {
        const dbSuggestions = await checkDebertaUpdates();
        if (dbSuggestions.length > 0) {
          _logger.info(`[GuardClaw Advisor] DeBERTa: ${dbSuggestions.length} update suggestion(s)`);
          if (_config.deberta?.autoUpdate !== false) {
            for (const s of dbSuggestions) {
              _data2.suggestions.push(s);
              const result = await acceptSuggestion(s.id);
              if (result.ok) {
                _logger.info(
                  `[GuardClaw Advisor] DeBERTa auto-updated to ${s.suggestedValue}. Restart the injection service (port 8404) to load the new model.`
                );
              } else {
                _logger.warn(`[GuardClaw Advisor] DeBERTa auto-update failed: ${result.message}`);
              }
            }
          } else {
            allNew.push(...dbSuggestions);
          }
        }
      } catch (err) {
        _logger.warn(`[GuardClaw Advisor] DeBERTa check failed: ${String(err)}`);
      }
    }
    const benchmarkEnabled = _config.benchmark?.enabled !== false;
    const benchmarkRuns = Math.min(_config.benchmark?.runs ?? 3, BENCHMARK_PROMPTS.length);
    if (benchmarkEnabled) {
      const privacy = getLiveConfig();
      const localEndpoint = privacy.localModel?.endpoint ?? "http://localhost:11434";
      const localModel = privacy.localModel?.model ?? DEFAULT_LOCAL_CLASSIFIER_MODEL;
      const providerType = privacy.localModel?.type ?? "openai-compatible";
      let currentBenchmark;
      try {
        currentBenchmark = await benchmarkModel(localEndpoint, localModel, providerType, benchmarkRuns);
        _logger.info(`[GuardClaw Advisor] Current judge benchmark: ${(currentBenchmark.jsonSuccessRate * 100).toFixed(0)}% JSON success, ${currentBenchmark.avgLatencyMs}ms avg`);
      } catch (err) {
        _logger.warn(`[GuardClaw Advisor] Benchmark of current model failed: ${String(err)}`);
      }
      for (const s of allNew.filter((s2) => s2.type === "local_model")) {
        const candidateModel = s.suggestedValue ?? "";
        if (!candidateModel) continue;
        try {
          const candidateBenchmark = await benchmarkModel(localEndpoint, candidateModel, providerType, benchmarkRuns);
          s.benchmarkCandidate = candidateBenchmark;
          if (currentBenchmark) s.benchmarkCurrent = currentBenchmark;
          _logger.info(
            `[GuardClaw Advisor] Candidate ${candidateModel} benchmark: ${(candidateBenchmark.jsonSuccessRate * 100).toFixed(0)}% JSON success, ${candidateBenchmark.avgLatencyMs}ms avg`
          );
          if (currentBenchmark && candidateBenchmark.jsonSuccessRate < currentBenchmark.jsonSuccessRate * 0.95 && candidateBenchmark.avgLatencyMs > currentBenchmark.avgLatencyMs * 1.05) {
            s.status = "dismissed";
            _logger.info(`[GuardClaw Advisor] Dismissed ${candidateModel} \u2014 benchmark below current model`);
          }
        } catch {
        }
      }
    }
    for (const s of allNew) {
      if (s.status !== "dismissed") {
        _data2.suggestions.push(s);
      }
    }
    _data2.lastCheckedAt = (/* @__PURE__ */ new Date()).toISOString();
    await saveAdvisorData();
    const pending = _data2.suggestions.filter((s) => s.status === "pending").length;
    _logger.info(`[GuardClaw Advisor] Check complete \u2014 ${pending} pending suggestion(s)`);
  } finally {
    _running = false;
  }
}
async function acceptSuggestion(id) {
  const suggestion = _data2.suggestions.find((s) => s.id === id);
  if (!suggestion) return { ok: false, message: "Suggestion not found" };
  if (suggestion.status !== "pending") return { ok: false, message: `Already ${suggestion.status}` };
  try {
    if (suggestion.type === "openrouter_cheaper" || suggestion.type === "openrouter_best_value" || suggestion.type === "openrouter_best") {
      const details = suggestion.details;
      const tier = details?.tier;
      const newModel = suggestion.suggestedValue;
      if (!tier || !newModel) return { ok: false, message: "Missing tier or model in suggestion" };
      const cfg = getLiveConfig();
      const routers = cfg.routers ?? {};
      if (!routers["token-saver"]) routers["token-saver"] = {};
      if (!routers["token-saver"].options) routers["token-saver"].options = {};
      const tiers = routers["token-saver"].options.tiers ?? {};
      tiers[tier] = { provider: "openrouter", model: newModel };
      routers["token-saver"].options.tiers = tiers;
      updateLiveConfig({ routers });
      const configPath = join10(HOME4, ".openclaw", "guardclaw.json");
      let fileCfg = {};
      try {
        fileCfg = JSON.parse(await readFile4(configPath, "utf-8"));
      } catch {
      }
      if (!fileCfg.privacy) fileCfg.privacy = {};
      const priv = fileCfg.privacy;
      if (!priv.routers) priv.routers = {};
      const fileRouters = priv.routers;
      if (!fileRouters["token-saver"]) fileRouters["token-saver"] = {};
      if (!fileRouters["token-saver"].options) fileRouters["token-saver"].options = {};
      const fileTiers = fileRouters["token-saver"].options.tiers ?? {};
      fileTiers[tier] = { provider: "openrouter", model: newModel };
      fileRouters["token-saver"].options.tiers = fileTiers;
      await writeFile3(configPath, JSON.stringify(fileCfg, null, 2), { encoding: "utf-8", mode: 384 });
      suggestion.status = "accepted";
      await saveAdvisorData();
      return { ok: true, message: `Token-saver ${tier} tier updated to ${newModel}. Config saved.` };
    }
    if (suggestion.type === "local_model") {
      const newModel = suggestion.suggestedValue;
      if (!newModel) return { ok: false, message: "Missing model name" };
      updateLiveConfig({ localModel: { ...getLiveConfig().localModel, model: newModel } });
      const configPath = join10(HOME4, ".openclaw", "guardclaw.json");
      let fileCfg = {};
      try {
        fileCfg = JSON.parse(await readFile4(configPath, "utf-8"));
      } catch {
      }
      if (!fileCfg.privacy) fileCfg.privacy = {};
      const priv = fileCfg.privacy;
      if (!priv.localModel) priv.localModel = {};
      priv.localModel.model = newModel;
      await writeFile3(configPath, JSON.stringify(fileCfg, null, 2), { encoding: "utf-8", mode: 384 });
      suggestion.status = "accepted";
      await saveAdvisorData();
      return {
        ok: true,
        message: `Local model updated to ${newModel}. ${suggestion.pullCommand ? `Pull it with: ${suggestion.pullCommand}` : "Pull the model before use."}`
      };
    }
    if (suggestion.type === "deberta_update") {
      const newModel = suggestion.suggestedValue;
      if (!newModel) return { ok: false, message: "Missing model ID" };
      const configPath = join10(HOME4, ".openclaw", "guardclaw.json");
      let fileCfg = {};
      try {
        fileCfg = JSON.parse(await readFile4(configPath, "utf-8"));
      } catch {
      }
      if (!fileCfg.injection) fileCfg.injection = {};
      fileCfg.injection.deberta_model = newModel;
      await writeFile3(configPath, JSON.stringify(fileCfg, null, 2), { encoding: "utf-8", mode: 384 });
      suggestion.status = "accepted";
      await saveAdvisorData();
      triggerDebertaReload(newModel).then((r) => {
        if (r.ok) {
          _logger?.info(`[GuardClaw Advisor] DeBERTa hot-swap complete: ${r.message}`);
        } else {
          _logger?.info(`[GuardClaw Advisor] DeBERTa service unreachable (${r.message}) \u2014 new model active on next startup`);
        }
      }).catch(() => {
      });
      return { ok: true, message: `DeBERTa model updated to ${newModel}. Hot-reloading injection service\u2026` };
    }
    return { ok: false, message: `Unknown suggestion type: ${suggestion.type}` };
  } catch (err) {
    return { ok: false, message: String(err) };
  }
}
function dismissSuggestion(id) {
  const s = _data2.suggestions.find((s2) => s2.id === id);
  if (s) {
    s.status = "dismissed";
    saveAdvisorData().catch(() => {
    });
  }
}
function getSuggestions(statusFilter) {
  return _data2.suggestions.filter((s) => !statusFilter || s.status === statusFilter);
}
function getLastCheckedAt() {
  return _data2.lastCheckedAt;
}
async function initModelAdvisor(config, openrouterApiKey, logger) {
  if (!config.enabled) return;
  _config = config;
  _openrouterApiKey = openrouterApiKey;
  _logger = logger;
  await loadAdvisorData();
  const intervalWeeks = config.checkIntervalWeeks ?? 2;
  const intervalMs = intervalWeeks * MS_PER_WEEK;
  const lastChecked = _data2.lastCheckedAt ? new Date(_data2.lastCheckedAt).getTime() : 0;
  if (Date.now() - lastChecked > intervalMs) {
    setTimeout(() => runAdvisorChecks().catch((err) => {
      _logger.warn(`[GuardClaw Advisor] Startup check failed: ${String(err)}`);
    }), 1e4);
  }
  if (_scheduleTimer) clearInterval(_scheduleTimer);
  _scheduleTimer = setInterval(() => {
    runAdvisorChecks().catch((err) => {
      _logger.warn(`[GuardClaw Advisor] Scheduled check failed: ${String(err)}`);
    });
  }, intervalMs);
  if (_scheduleTimer && typeof _scheduleTimer === "object" && "unref" in _scheduleTimer) {
    _scheduleTimer.unref();
  }
  logger.info(`[GuardClaw Advisor] Initialized (interval: ${intervalWeeks}w, ${getSuggestions("pending").length} pending suggestion(s))`);
}

// src/stats-dashboard.ts
var GUARDCLAW_CONFIG_PATH2 = join11(process.env.HOME ?? "/tmp", ".openclaw", "guardclaw.json");
var GUARDCLAW_INJECTIONS_PATH3 = join11(process.env.HOME ?? "/tmp", ".openclaw", "guardclaw-injections.json");
var GUARDCLAW_STATS_PATH2 = join11(process.env.HOME ?? "/tmp", ".openclaw", "guardclaw-stats.json");
var CENTRASE_LOGO_B64 = "iVBORw0KGgoAAAANSUhEUgAAA/IAAAFrCAYAAABylLKaAAChMElEQVR4nO3dCZwcZZk/8N/7VvdMLm4mMwTIwS1RQY4Aopj1WvHcdU3WC4n/VW5BbhKQNFcOLgVBhFUJqOuarPeueAsKCHKJAiJnDiAzGSCQe6a76v1/nup6e96uqZ7pmenu6e75fTVMn9XVVdXd9bzH8yhjoEFERERERETUpGYtxgnQeB8aWIvBwnvm41G5zCCeiIiIiIiIqIEwkCciIiIiIiJqIAzkiYiIiIiIiBoIA3kiIiIiIiKiBsJAnoiIiIiIiKiBMJAnIiIiIiIiaiAM5ImIiIiIiIgaCAN5IiIiIiIiogbCQJ6IiIiIiIiogTCQJyIiIiIiImogDOSJiIiIiIiIGggDeSIiIiIiIqIGwkCeiIiIiIiIqIEwkCciIiIiIiJqIAzkiYiIiIiIiBoIA3kiIiIiIiKiBsJAnoiIiIiIiKiBMJAnIiIiIiIiaiAM5ImIiIiIiIgaCAN5IiIiIiIiogbCQJ6ogpRCMNDnKrq/5HWxYgVUiafz80pEREREREhxGxBVjjFhsB0McH/KvT96fJE5c2Ccq+79JZdLRERERERjBwN5ohqJet8DN3g//TuYFASYaXxM1h68XoP12xv8/ap5WBc9hME7EREREREVYSBPVB2FnnkJ4CV4twG8XP/Ct3Egsvi4DxwEDa21RPj5D+QWBZx2G1b7Cj9653j8PtZDT0REREREYxzn3BJVhzt8PmXnvnd1d6pTluE038fSnMoH8UrBxLvdDTBVG5xx50ZcuWAFdpHPaoZ7ioiIiIiIGMgT1UQYpy9dD33ZHR2XauCf5bpSfQ1pEszHn6Q0lPaw3+tbcfW5y7ArA3kiIiIiIhLskSeq/ucq7E0/ehw+bwze7Pa+Gx322Kvwny5+sgnyPfUmwI5bFC6ameFUGCIiIiIiYiBPVFGZEgnqur6JfXMGx9qednu7ch5pL8efHPXcTztmOj7K3UVEREREROyRJ6qgSxLqwmeAINWC4+D0tJezLDvcXmloA/gA/nXeMrRwhxERERERjW0M5IkqKKku/JTfYDs/wBuHsayw594ECBTgKYXWndI4tFLrSkREREREjYmBPFGVPdaJN0ggPtLlKCDVu3XoDQJERERERNRcGMgTVdnWALuWykw/FMbAz3loc2+TknYjXT8iIiIiImosDOSJqqzFh+crBHao/LApmJRXvIw5c0bWOEBERERERI2HgTxRhcV7yVs9vOaZigyt91QWr410OURERERE1NgYyBNVWLyX3O/FkzIyvhLLTmk8ZS8rJ0M+h9gTEREREY0dDOSJquy6z6FbBXhuqM8zpriUnR8gN74Vf3bu1zaY5xB7IiIiIqKxg4E8UQ1s1fhB0u1JCfBM9KlUqvjzmVK4a/En8fpg5e6IiIiIiKi5MQggqoH3TcA9RuHx+O2SAE/p4jn1qqgfPnpcgE3bt+J71V1LIiIiIiJqBAzkiaogE7ssQ993SGFpoNBtP3Q6+meCgefPGxlVn8KSRZ9AN3cWERERERExkCeqIDtnPR7ICxkWP1HhAj/AczJ8Xh7oR/PgZT689MzH5sUr6YkPNBZ+/Tj8jTuKiIiIiIgEA3miGrr6OLw8WeF842OZMdioFDwJ6mU+vPTM23nxEtAbg1/uOAmnM4gnIiIiIiJXqugaEY1IlHxO/iXMdM/LzEMvgB/NW4b/28HDm4IcDs4ptMl8eU/h9RbgqdYu3L/kfGzk7iAiIiIiojgG8kQVtmIFzJw5/W/PxIbcL8sH9A8BeCQp8Jdh+sxKT0REREREcRxaT1RhkthuxQqoeODuXhbyGPlng/j4/W6deCIiIiIiIos98kRVCubnlPEY93o8kBfskSciIiIiojj2yBMRERERERE1EAbyRERERERERA2EgTwRERERERFRA2EgT0RERERERNRAGMgTERERERERNRAG8kREREREREQNhIE8ERERERERUQNhIE9ERERERETUQBjIExERERERETUQBvJEREREREREDYSBPBEREREREVEDYSBPRERERERE1EAYyBMRERERERE1EAbyRERERERERA2EgTwRERERERFRA2EgT+RQCsGKFVBJGyUT/XXu1+59mej58c9VdBs/h0REREREVBEM5IkcxkDPmQOT9BmZmQ/gw/ujYD6IB/LyfLndbQyIbuvHeUy4nFINCERERERERC4G8kQDKwTrEsBnouuxYL9f7/vcufDjPfnxz118GaWWSURERERE5EoVXSMiEfaqxzdFZhla1ucw8wyNN2c19kxpTA2AccYgpQJsDTReOe1WrD35W/jHx7+BhwF0SmCf0CM/2FB7IiIiIiKiklSpYb9ElHfuMkzeDPwLDN6BFCapKAxX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yw7wLHbpvT5sSHA8FNXDYx15IiIiIqLmwUCeqLLCXu+bb4aPTavnw6iVkFC+0sJOeSgoz8BgHSYGZ5uzXuiJB/KHhin0WUeeiIiIiKiZMJAnqhLzFWyA2XoafDxX2SV70Qh7GPi9L2Jb7ynmwtVdSbXtiYiIiIio+TCQJ6owO4xdAmqzqPMVzNjnJJjg7miUe3ECPLeMXBE1wP1hJ7tkqP8LVPZEc81LLw5Y256IiIiIiJoKT/iJqpC5Pgzio4DanPCbjeaK1eciyC0FsDF8kE2AF5aOi0beS9BeCNyjefC2zJzL97fCx9eue/vq08OGgkh8WD0RERERETUnBvJEFfYhwIuC+OLP1+JVP8SmlR+Db26DUpsKtwcwCKJ68G7gHu+NN8E2aG8Ftuv5d7N45bdPPxZ9Je4YyBMRERERjRmsK01UYTbBXLzcWxTcbwBWff3YY/HNXxy059uRVkcjUG+BVrv1qyoXBvboBmQIfepP7TutvLPzHGyVu2yPvwzjj5WYIyIiIiKiJsdAnqiK3CH2Ebkc3HEHfKXW/MYY/E5unHkjJjzxwuTJaO2dBH+iwrbxm3ZRz6x7+UpsTlqu7fGfMyd/1V02dygRERERUXNjIE9URRJwZ5z560ohFwXhhQA/Cva3AOtW5h/1WrmLjwftDOKJiIiIiMYAzpEnqhEJ5hcmZJRnlnkiIiIiIhoKBvJEVTYzKkfn9swPVrpuMKwVT0REREQ0djGQJ6qyoSSjK/ex7MUnIiIiIhq7GMgTERERERERNRAG8kREREREREQNhIE8ERERERERUQNhIE9ERERERETUQBjIExERERERETUQBvJEREREREREDYSBPBEREREREVEDYSBPRERERERE1EAYyBMRERERERE1EAbyRERERERERA2EgTwRERERERFRA2EgT0RERERERNRAGMgTERERERERNRAG8kREREREREQNhIE8ERERERERUQNhIE9ERERERETUQBjIExERERERETUQBvJEREREREREDYSBPBEREREREVEDYSBPRERERERE1EAYyBMRERERERGhcfx/gRHitOKGg5wAAAAASUVORK5CYII=";
function saveGuardClawConfig(privacy) {
  try {
    const dir = join11(process.env.HOME ?? "/tmp", ".openclaw");
    mkdirSync2(dir, { recursive: true });
    let existing = {};
    try {
      existing = JSON.parse(readFileSync2(GUARDCLAW_CONFIG_PATH2, "utf-8"));
    } catch {
    }
    const updated = { ...existing, privacy };
    writeFileSync2(GUARDCLAW_CONFIG_PATH2, JSON.stringify(updated, null, 2), { encoding: "utf-8", mode: 384 });
  } catch {
  }
}
var deps = null;
function initDashboard(d) {
  deps = d;
}
var MAX_SENDER_ID_LENGTH = 128;
var MAX_CORRECTION_MESSAGE_LENGTH = 2e3;
function parseSenderId(raw) {
  const s = typeof raw === "string" ? raw.trim() : "";
  if (!s || s.length > MAX_SENDER_ID_LENGTH) return null;
  return s;
}
function readBody(req) {
  return new Promise((resolve3, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve3(Buffer.concat(chunks).toString("utf-8")));
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
  if (req.method === "GET" && sub === "/api/synthesis-stats") {
    try {
      const raw = readFileSync2(GUARDCLAW_STATS_PATH2, "utf-8");
      const stats = JSON.parse(raw);
      json(res, stats.synthesis ?? {});
    } catch {
      json(res, {});
    }
    return true;
  }
  if (req.method === "GET" && sub === "/api/current-loop-highest-level") {
    const sessionKey2 = parsedUrl.searchParams.get("sessionKey") ?? void 0;
    json(res, getCurrentLoopHighestLevel(sessionKey2));
    return true;
  }
  if (req.method === "GET" && sub === "/api/last-turn-tokens") {
    const sessionKey2 = parsedUrl.searchParams.get("sessionKey") ?? void 0;
    const data = getLastTurnTokens(sessionKey2);
    if (!data) {
      json(res, { error: "no last-turn router tokens yet" }, 404);
      return true;
    }
    json(res, data);
    return true;
  }
  if (req.method === "GET" && sub === "/api/reply-model-origin") {
    const sessionKey2 = parsedUrl.searchParams.get("sessionKey") ?? void 0;
    const origin = getLastReplyModelOrigin(sessionKey2);
    const loopSummary = getLastReplyLoopSummary(sessionKey2);
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
        if (d.level === "S0") continue;
        events.push({
          sessionKey: state.sessionKey,
          level: d.level,
          checkpoint: d.checkpoint,
          reason: d.reason,
          timestamp: d.timestamp
        });
      }
    });
    try {
      const raw = readFileSync2(GUARDCLAW_INJECTIONS_PATH3, "utf-8");
      const injections = JSON.parse(raw);
      for (const entry of injections) {
        events.push({
          sessionKey: entry.session,
          level: "S0",
          checkpoint: "onUserMessage",
          reason: `${entry.action} (score ${entry.score}) [${entry.source}]: ${entry.patterns.join(", ")} \u2014 "${entry.preview}"`,
          timestamp: new Date(entry.ts).getTime()
        });
      }
    } catch {
    }
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
        pipeline: cfgAny.pipeline,
        injection: liveConfig.injection,
        budget: liveConfig.budget,
        modelAdvisor: liveConfig.modelAdvisor
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
      if (body.message.length > MAX_CORRECTION_MESSAGE_LENGTH) {
        json(res, { error: `message too long (max ${MAX_CORRECTION_MESSAGE_LENGTH} chars)` }, 400);
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
  if (req.method === "GET" && sub === "/api/banned") {
    const banned = getLiveInjectionConfig().banned_senders ?? [];
    json(res, { banned });
    return true;
  }
  if (req.method === "POST" && sub === "/api/unban") {
    try {
      const body = JSON.parse(await readBody(req));
      const senderId = parseSenderId(body.senderId);
      if (!senderId) {
        json(res, { error: "senderId required (max 128 chars)" }, 400);
        return true;
      }
      const newBanned = (getLiveInjectionConfig().banned_senders ?? []).filter((id) => id !== senderId);
      updateLiveInjectionConfig({ banned_senders: newBanned });
      let cfg = {};
      try {
        cfg = JSON.parse(readFileSync2(GUARDCLAW_CONFIG_PATH2, "utf-8"));
      } catch {
      }
      if (!cfg.privacy) cfg.privacy = {};
      const priv = cfg.privacy;
      if (!priv.injection) priv.injection = {};
      priv.injection.banned_senders = newBanned;
      writeFileSync2(GUARDCLAW_CONFIG_PATH2, JSON.stringify(cfg, null, 2), { encoding: "utf-8", mode: 384 });
      json(res, { ok: true });
    } catch (err) {
      json(res, { error: String(err) }, 400);
    }
    return true;
  }
  if (req.method === "GET" && sub === "/api/exempt") {
    const exempt = getLiveInjectionConfig().exempt_senders ?? [];
    json(res, { exempt });
    return true;
  }
  if (req.method === "POST" && sub === "/api/exempt") {
    try {
      const body = JSON.parse(await readBody(req));
      const senderId = parseSenderId(body.senderId);
      if (!senderId) {
        json(res, { error: "senderId required (max 128 chars)" }, 400);
        return true;
      }
      const current = getLiveInjectionConfig().exempt_senders ?? [];
      if (current.includes(senderId)) {
        json(res, { ok: true, already: true });
        return true;
      }
      const newExempt = [...current, senderId];
      updateLiveInjectionConfig({ exempt_senders: newExempt });
      let cfg = {};
      try {
        cfg = JSON.parse(readFileSync2(GUARDCLAW_CONFIG_PATH2, "utf-8"));
      } catch {
      }
      if (!cfg.privacy) cfg.privacy = {};
      const priv = cfg.privacy;
      if (!priv.injection) priv.injection = {};
      priv.injection.exempt_senders = newExempt;
      writeFileSync2(GUARDCLAW_CONFIG_PATH2, JSON.stringify(cfg, null, 2), { encoding: "utf-8", mode: 384 });
      json(res, { ok: true });
    } catch (err) {
      json(res, { error: String(err) }, 400);
    }
    return true;
  }
  if (req.method === "DELETE" && sub.startsWith("/api/exempt/")) {
    try {
      const senderId = parseSenderId(decodeURIComponent(sub.slice("/api/exempt/".length)));
      if (!senderId) {
        json(res, { error: "senderId required (max 128 chars)" }, 400);
        return true;
      }
      const newExempt = (getLiveInjectionConfig().exempt_senders ?? []).filter((id) => id !== senderId);
      updateLiveInjectionConfig({ exempt_senders: newExempt });
      let cfg = {};
      try {
        cfg = JSON.parse(readFileSync2(GUARDCLAW_CONFIG_PATH2, "utf-8"));
      } catch {
      }
      if (!cfg.privacy) cfg.privacy = {};
      const priv = cfg.privacy;
      if (!priv.injection) priv.injection = {};
      priv.injection.exempt_senders = newExempt;
      writeFileSync2(GUARDCLAW_CONFIG_PATH2, JSON.stringify(cfg, null, 2), { encoding: "utf-8", mode: 384 });
      json(res, { ok: true });
    } catch (err) {
      json(res, { error: String(err) }, 400);
    }
    return true;
  }
  if (req.method === "GET" && sub === "/api/suggestions") {
    const statusFilter = parsedUrl.searchParams.get("status");
    const suggestions = getSuggestions(statusFilter ?? void 0);
    json(res, { suggestions, lastCheckedAt: getLastCheckedAt() });
    return true;
  }
  if (req.method === "POST" && sub.startsWith("/api/suggestions/") && sub.endsWith("/accept")) {
    const id = sub.slice("/api/suggestions/".length, -"/accept".length);
    if (!id) {
      json(res, { error: "id required" }, 400);
      return true;
    }
    try {
      const result = await acceptSuggestion(id);
      json(res, result, result.ok ? 200 : 400);
    } catch (err) {
      json(res, { error: String(err) }, 500);
    }
    return true;
  }
  if (req.method === "POST" && sub.startsWith("/api/suggestions/") && sub.endsWith("/dismiss")) {
    const id = sub.slice("/api/suggestions/".length, -"/dismiss".length);
    if (!id) {
      json(res, { error: "id required" }, 400);
      return true;
    }
    dismissSuggestion(id);
    json(res, { ok: true });
    return true;
  }
  if (req.method === "POST" && sub === "/api/advisor/run") {
    runAdvisorChecks().catch(() => {
    });
    json(res, { ok: true, message: "Advisor check triggered" });
    return true;
  }
  if (req.method === "GET" && sub === "/api/budget") {
    const cfg = getLiveConfig().budget;
    const snapshot = getBudgetSnapshot();
    json(res, {
      enabled: cfg?.enabled ?? false,
      dailyCap: cfg?.dailyCap ?? null,
      monthlyCap: cfg?.monthlyCap ?? null,
      warnAt: cfg?.warnAt ?? null,
      action: cfg?.action ?? "warn",
      dailyCost: getDailyCost(),
      monthlyCost: getMonthlyCost(),
      raw: snapshot
    });
    return true;
  }
  if (req.method === "GET" && sub === "/api/models") {
    const liveConfig = getLiveConfig();
    const endpoint = parsedUrl.searchParams.get("endpoint") ?? liveConfig.localModel?.endpoint ?? "http://localhost:11434";
    const type = parsedUrl.searchParams.get("type") ?? liveConfig.localModel?.type ?? "openai-compatible";
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5e3);
      let models = [];
      if (type === "ollama-native") {
        const r = await fetch(`${endpoint}/api/tags`, { signal: controller.signal });
        clearTimeout(timer);
        if (r.ok) {
          const data = await r.json();
          models = (data.models ?? []).map((m) => m.name);
        }
      } else {
        const r = await fetch(`${endpoint}/v1/models`, { signal: controller.signal });
        clearTimeout(timer);
        if (r.ok) {
          const data = await r.json();
          models = (data.data ?? []).map((m) => m.id);
        }
      }
      json(res, { models });
    } catch {
      json(res, { models: [], error: "Could not reach model endpoint" });
    }
    return true;
  }
  if (req.method === "GET" && sub === "/api/prices/openrouter") {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8e3);
      const r = await fetch("https://openrouter.ai/api/v1/models", { signal: controller.signal });
      clearTimeout(timer);
      if (!r.ok) {
        json(res, { error: `HTTP ${r.status}` }, 502);
        return true;
      }
      const data = await r.json();
      const models = (data.data ?? []).filter((m) => m.pricing?.prompt || m.pricing?.completion).map((m) => ({
        id: m.id,
        inputPer1M: m.pricing?.prompt ? parseFloat(m.pricing.prompt) * 1e6 : null,
        outputPer1M: m.pricing?.completion ? parseFloat(m.pricing.completion) * 1e6 : null
      }));
      json(res, { models, fetchedAt: (/* @__PURE__ */ new Date()).toISOString() });
    } catch {
      json(res, { error: "Could not reach OpenRouter" }, 502);
    }
    return true;
  }
  return false;
}
function dashboardHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GuardClaw Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  :root{--bg-body:#3D4246;--bg-surface:#353a3e;--bg-card:#2a2e32;--bg-input:#3a3f44;--text-primary:#f0f0f0;--text-secondary:#a8b0b8;--text-tertiary:#6b7280;--border-subtle:#4a5058;--accent:#8DC63F;--accent-hover:#7ab032;--accent2:#006837;--radius-sm:6px;--radius-md:12px;--radius-lg:16px;--shadow-sm:0 1px 2px 0 rgba(0,0,0,.2);--shadow-card:0 2px 8px rgba(0,0,0,.2);--shadow-float:0 10px 15px -3px rgba(0,0,0,.3),0 4px 6px -2px rgba(0,0,0,.2);--font-sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;--font-mono:'JetBrains Mono','SFMono-Regular',ui-monospace,monospace}
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:var(--font-sans);background:var(--bg-surface);color:var(--text-primary);min-height:100vh;-webkit-font-smoothing:antialiased;line-height:1.6}

  .header{padding:12px 24px;background:#2a2e32;backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border-bottom:2px solid var(--accent2);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:50}
  .header-logo{height:36px;width:auto;display:block}
  .header-brand{display:flex;flex-direction:column;gap:1px}
  .header-subtitle{font-size:11px;font-weight:600;color:#fff;letter-spacing:.08em;text-transform:uppercase;opacity:.85}
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
  .card.cloud .card-value{color:#3b82f6}
  .card.local .card-value{color:#8DC63F}
  .card.proxy .card-value{color:#f59e0b}
  .card.privacy .card-value{color:#a78bfa}
  .card.cost .card-value{color:#ef4444}

  .chart-wrap{background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:16px 18px;margin-bottom:20px;box-shadow:var(--shadow-sm)}
  .chart-wrap h3{font-size:12px;color:var(--text-secondary);font-weight:600;margin-bottom:10px}

  .data-table{width:100%;border-collapse:collapse;background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:var(--radius-md);overflow:hidden}
  .data-table th,.data-table td{padding:10px 14px;font-size:13px;text-align:right}
  .data-table th{background:var(--bg-surface);color:var(--text-secondary);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
  .data-table th:first-child,.data-table td:first-child{text-align:left}
  .data-table tr:not(:last-child) td{border-bottom:1px solid var(--border-subtle)}
  .data-table tbody tr:hover{background:rgba(141,198,63,.05)}
  #detections-panel .data-table th,#detections-panel .data-table td{text-align:left}

  .info-bar{display:flex;gap:24px;padding:14px 0;font-size:12px;color:var(--text-tertiary)}

  .level-tag{display:inline-block;font-size:11px;font-weight:600;padding:3px 10px;border-radius:99px}
  .level-S0{background:rgba(239,68,68,.15);color:#ef4444}
  .level-S1{background:rgba(59,130,246,.15);color:#3b82f6}
  .level-S2{background:rgba(245,158,11,.15);color:#f59e0b}
  .level-S3{background:rgba(141,198,63,.15);color:#8DC63F}
  .checkpoint-tag{font-size:11px;padding:3px 8px;border-radius:99px;background:var(--bg-input);color:var(--text-secondary);font-weight:500}
  .session-key{font-family:var(--font-mono);font-size:12px;color:var(--text-secondary)}

  .empty-state{text-align:center;color:var(--text-tertiary);padding:48px 0;font-size:14px}

  .filter-bar{display:flex;gap:8px;margin-bottom:18px}
  .filter-btn{padding:7px 16px;border-radius:99px;border:1px solid var(--border-subtle);background:var(--bg-card);color:var(--text-secondary);cursor:pointer;font-size:12px;font-weight:500;transition:all .15s}
  .filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
  .filter-btn:hover{border-color:#d1d5db;color:var(--text-primary)}

  .config-section{background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:18px 20px;margin-bottom:14px;box-shadow:var(--shadow-sm)}
  .config-section h3{font-size:11px;color:var(--text-secondary);margin-bottom:14px;text-transform:uppercase;letter-spacing:.05em;font-weight:700}
  .field{margin-bottom:16px}
  .field label{display:block;font-size:12px;color:var(--text-secondary);margin-bottom:6px;font-weight:500}
  .field input,.field select{width:100%;padding:10px 14px;background:var(--bg-input);border:1px solid transparent;border-radius:var(--radius-sm);color:var(--text-primary);font-size:13px;outline:none;transition:all .15s}
  .field input[type=radio]{width:auto;padding:0;background:transparent;border:none;border-radius:0;flex-shrink:0;cursor:pointer;accent-color:var(--accent,#4f9cf9)}
  .field select{appearance:none;-webkit-appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%236e6e80' d='M2 4l4 4 4-4'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 14px center;padding-right:36px}
  .field input:hover,.field select:hover{background:#eaecf1}
  .field input:focus,.field select:focus{background:#3a3f44;border-color:var(--accent);box-shadow:0 0 0 3px rgba(141,198,63,.2)}

  .tag-list{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px;min-height:32px}
  .tag{background:var(--bg-input);color:var(--text-primary);padding:5px 12px;border-radius:99px;font-size:12px;font-weight:500;display:flex;align-items:center;gap:6px;border:1px solid var(--border-subtle)}
  .tag button{background:none;border:none;color:var(--text-tertiary);cursor:pointer;font-size:14px;line-height:1;transition:color .15s}
  .tag button:hover{color:#ef4444}
  .add-row{display:flex;gap:10px;margin-top:10px;align-items:center}
  .add-row input{flex:1;min-width:0}

  .btn{padding:10px 20px;border-radius:var(--radius-sm);border:none;cursor:pointer;font-size:13px;font-weight:500;transition:all .15s;white-space:nowrap;flex-shrink:0}
  .btn-primary{background:var(--accent);color:#fff}
  .btn-primary:hover{background:var(--accent-hover)}
  .btn-sm{padding:8px 16px;font-size:12px}
  .btn-outline{background:var(--bg-card);border:1px solid var(--border-subtle);color:var(--text-primary)}
  .btn-outline:hover{border-color:#d1d5db;background:var(--bg-surface)}
  .save-bar{display:flex;justify-content:flex-end;gap:10px;padding-top:14px;margin-top:10px}

  .badge{display:inline-block;font-size:10px;padding:3px 8px;border-radius:99px;margin-left:8px;vertical-align:middle;font-weight:600}
  .badge-hot{background:rgba(141,198,63,.15);color:#8DC63F}

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
  .chip.active{background:var(--accent);color:#fff;border-color:var(--accent)}
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
  .prompt-editor:focus{background:#3a3f44;box-shadow:0 0 0 3px rgba(141,198,63,.2)}
  .prompt-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
  .prompt-header h4{font-size:13px;color:var(--text-primary);font-weight:600}
  .prompt-actions{display:flex;gap:6px}
  .custom-badge{font-size:10px;padding:3px 8px;border-radius:99px;background:rgba(37,99,235,.08);color:var(--accent);font-weight:600;margin-left:8px}

  .test-panel{background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:18px 20px;margin-bottom:14px;box-shadow:var(--shadow-sm)}
  .test-input{width:100%;min-height:80px;padding:14px 16px;background:var(--bg-input);border:1px solid transparent;border-radius:var(--radius-md);color:var(--text-primary);font-size:13px;resize:vertical;outline:none;transition:all .15s}
  .test-input:hover{background:#eaecf1}
  .test-input:focus{background:#3a3f44;box-shadow:0 0 0 3px rgba(141,198,63,.2)}
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

  .suggestion-card{background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:var(--radius-md);padding:18px 20px;margin-bottom:12px;box-shadow:var(--shadow-sm);transition:border-color .15s}
  .suggestion-card:hover{border-color:#d1d5db}
  .suggestion-card.accepted{opacity:.55}
  .suggestion-card.dismissed{opacity:.4}
  .suggestion-card .sc-head{display:flex;align-items:flex-start;gap:12px}
  .suggestion-card .sc-icon{width:36px;height:36px;border-radius:var(--radius-sm);display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;background:var(--bg-surface)}
  .suggestion-card .sc-title{font-size:14px;font-weight:600;color:var(--text-primary);margin-bottom:3px}
  .suggestion-card .sc-desc{font-size:12px;color:var(--text-secondary);line-height:1.5}
  .suggestion-card .sc-actions{margin-left:auto;display:flex;gap:8px;flex-shrink:0}
  .suggestion-card .sc-meta{display:flex;gap:16px;margin-top:12px;padding-top:12px;border-top:1px solid var(--border-subtle);flex-wrap:wrap}
  .suggestion-card .sc-meta-item{font-size:11px;color:var(--text-tertiary)}
  .suggestion-card .sc-meta-item strong{color:var(--text-primary);font-weight:600}
  .suggestion-card .sc-bench{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}
  .suggestion-card .sc-bench-col{background:var(--bg-surface);border-radius:var(--radius-sm);padding:8px 12px;font-size:11px}
  .suggestion-card .sc-bench-col .sc-bench-label{color:var(--text-tertiary);margin-bottom:4px;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
  .suggestion-card .sc-bench-col .sc-bench-val{color:var(--text-primary);font-size:13px;font-weight:700}
  .suggestion-card code{font-family:var(--font-mono);font-size:11px;background:var(--bg-input);padding:2px 6px;border-radius:3px;color:var(--accent)}
  .saving-pill{display:inline-block;font-size:11px;font-weight:700;padding:3px 10px;border-radius:99px;background:rgba(141,198,63,.15);color:#8DC63F;margin-left:8px}
  .budget-bar-warn .budget-bar-fill{background:#f59e0b !important}
  .budget-bar-over .budget-bar-fill{background:#ef4444 !important}
  .adv-toggle .adv-arrow{font-size:10px;transition:transform .2s;display:inline-block}
  .adv-toggle.open .adv-arrow{transform:rotate(90deg)}
  .adv-body{display:none}
  .adv-body.open{display:block}

  ::-webkit-scrollbar{width:6px;height:6px}
  ::-webkit-scrollbar-track{background:transparent}
  ::-webkit-scrollbar-thumb{background:#4a5058;border-radius:3px}
  ::-webkit-scrollbar-thumb:hover{background:#6b7280}
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <img class="header-logo" src="data:image/png;base64,${CENTRASE_LOGO_B64}" alt="Centrase">
    <div class="header-brand">
      <span class="header-subtitle">GuardClaw</span>
    </div>
  </div>
  <div class="header-right">
    <span class="status-dot warn" id="status-dot"></span>
    <span id="status-text" data-i18n="header.connecting">Connecting...</span>
    <span id="last-updated"></span>
    <button class="btn btn-sm btn-outline" onclick="refreshAll()">Refresh</button>
  </div>
</div>

<div class="tabs">
  <div class="tab active" data-tab="stats" data-i18n="tab.overview">Overview</div>
  <div class="tab" data-tab="sessions" data-i18n="tab.sessions">Sessions</div>
  <div class="tab" data-tab="detections" data-i18n="tab.detections">Detection Log</div>
  <div class="tab" data-tab="rules"><span data-i18n="tab.rules">Router Rules</span> <span class="badge badge-hot">live</span></div>
  <div class="tab" data-tab="config"><span data-i18n="tab.config">Configuration</span> <span class="badge badge-hot">live</span></div>
  <div class="tab" data-tab="banned">Access Control</div>
  <div class="tab" data-tab="advisor">Advisor <span class="badge badge-hot" id="advisor-badge" style="display:none">!</span></div>
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

  <!-- Synthesis Latency -->
  <div id="synthesis-stats-section" style="display:none;margin:18px 0 0;">
    <h3 style="margin-bottom:10px;font-size:14px;color:var(--text-secondary);">S3 Synthesis Latency</h3>
    <table class="data-table">
      <thead><tr><th>Source</th><th>Count</th><th>Avg</th><th>Min</th><th>Max</th><th>p95</th><th>Failures</th></tr></thead>
      <tbody id="synthesis-stats-body"><tr><td colspan="7" class="empty-state">No synthesis data yet \u2014 enable s3Policy: synthesize to start collecting</td></tr></tbody>
    </table>
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
    <button class="filter-btn" onclick="filterDetections('S0',this)">S0</button>
    <button class="filter-btn" onclick="filterDetections('S1',this)">S1</button>
    <button class="filter-btn" onclick="filterDetections('S2',this)">S2</button>
    <button class="filter-btn" onclick="filterDetections('S3',this)">S3</button>
  </div>
  <table class="data-table">
    <thead><tr><th data-i18n="det.time">Time</th><th data-i18n="det.session">Session</th><th data-i18n="det.level">Level</th><th data-i18n="det.checkpoint">Checkpoint</th><th data-i18n="det.reason">Reason</th></tr></thead>
    <tbody id="detections-body"><tr><td colspan="5" class="empty-state" data-i18n="det.empty">No detections yet</td></tr></tbody>
  </table>
</div>

<!-- Advisor -->
<div id="advisor-panel" class="panel">
  <!-- Budget -->
  <div class="config-section" id="budget-section" style="display:none">
    <h3>Cloud Budget</h3>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">
      <div>
        <div class="card-label">Today</div>
        <div style="margin-top:6px">
          <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
            <span id="budget-daily-cost" style="font-weight:700;color:var(--text-primary)">$0.00</span>
            <span id="budget-daily-cap" style="color:var(--text-tertiary)">cap: \u2014</span>
          </div>
          <div style="height:8px;background:var(--bg-input);border-radius:4px;overflow:hidden">
            <div id="budget-daily-bar" style="height:100%;width:0%;border-radius:4px;background:var(--accent);transition:width .4s"></div>
          </div>
        </div>
      </div>
      <div>
        <div class="card-label">This Month</div>
        <div style="margin-top:6px">
          <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
            <span id="budget-monthly-cost" style="font-weight:700;color:var(--text-primary)">$0.00</span>
            <span id="budget-monthly-cap" style="color:var(--text-tertiary)">cap: \u2014</span>
          </div>
          <div style="height:8px;background:var(--bg-input);border-radius:4px;overflow:hidden">
            <div id="budget-monthly-bar" style="height:100%;width:0%;border-radius:4px;background:var(--accent);transition:width .4s"></div>
          </div>
        </div>
      </div>
    </div>
    <div style="font-size:11px;color:var(--text-tertiary)" id="budget-action-label"></div>
    <div style="margin-top:16px;padding-top:16px;border-top:1px solid var(--border-subtle);display:flex;flex-direction:column;gap:10px">
      <div style="font-size:12px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.05em">Budget Limits</div>
      <div class="form-row">
        <label>Daily Cap (USD) <span class="hint-inline">Leave empty to disable</span></label>
        <input type="number" id="cfg-budget-daily" min="0" step="0.01" placeholder="e.g. 5.00" class="input-sm">
      </div>
      <div class="form-row">
        <label>Monthly Cap (USD)</label>
        <input type="number" id="cfg-budget-monthly" min="0" step="0.01" placeholder="e.g. 50.00" class="input-sm">
      </div>
      <div class="form-row">
        <label>Warn At (%) <span class="hint-inline">Show warning when this % of cap is reached</span></label>
        <input type="number" id="cfg-budget-warn" min="50" max="99" step="5" value="80" class="input-sm">
      </div>
      <div class="form-row">
        <label>When Cap Reached</label>
        <select id="cfg-budget-action" class="input-sm">
          <option value="warn">Warn only</option>
          <option value="block">Block requests</option>
        </select>
      </div>
      <button onclick="saveBudgetSettings()" class="btn btn-primary" style="align-self:flex-start">Save Budget</button>
    </div>
  </div>

  <!-- Advisor Settings -->
  <details style="margin-bottom:20px">
    <summary style="cursor:pointer;font-weight:600;font-size:13px;color:var(--text-secondary);padding:10px 0;list-style:none">&#9881; Advisor Settings</summary>
    <div style="padding:14px 0;display:flex;flex-direction:column;gap:12px">
      <div class="form-row">
        <label>Enabled</label>
        <div class="toggle-wrap"><input type="checkbox" id="cfg-adv-enabled" class="toggle"><label for="cfg-adv-enabled" class="toggle-label"></label></div>
      </div>
      <div class="form-row">
        <label>Check Interval (weeks)</label>
        <input type="number" id="cfg-adv-interval" min="1" max="52" step="1" class="input-sm" value="2">
      </div>
      <div class="form-row">
        <label>Min Savings to Suggest (%)</label>
        <input type="number" id="cfg-adv-savings" min="5" max="90" step="5" class="input-sm" value="20">
      </div>
      <div class="form-row">
        <label>Min Free Disk Space (GB)</label>
        <input type="number" id="cfg-adv-disk" min="1" max="500" step="1" class="input-sm" value="10">
      </div>
      <div class="form-row">
        <label>OpenRouter API Key <span class="hint-inline">Required for cloud model pricing suggestions</span></label>
        <input type="password" id="cfg-adv-orkey" placeholder="sk-or-..." class="input-full">
      </div>
      <div class="form-row">
        <label>Check OpenRouter Models</label>
        <div class="toggle-wrap"><input type="checkbox" id="cfg-adv-or" class="toggle" checked><label for="cfg-adv-or" class="toggle-label"></label></div>
      </div>
      <div class="form-row">
        <label>Check Local Models (LLMFit)</label>
        <div class="toggle-wrap"><input type="checkbox" id="cfg-adv-llmfit" class="toggle" checked><label for="cfg-adv-llmfit" class="toggle-label"></label></div>
      </div>
      <div class="form-row">
        <label>Check DeBERTa Updates</label>
        <div class="toggle-wrap"><input type="checkbox" id="cfg-adv-deberta" class="toggle" checked><label for="cfg-adv-deberta" class="toggle-label"></label></div>
      </div>
      <div class="form-row">
        <label>Auto-apply DeBERTa Updates <span class="hint-inline">Apply new classifier models in-place without confirmation</span></label>
        <div class="toggle-wrap"><input type="checkbox" id="cfg-adv-autoupdate" class="toggle" checked><label for="cfg-adv-autoupdate" class="toggle-label"></label></div>
      </div>
      <button onclick="saveAdvisorSettings()" class="btn btn-primary" style="align-self:flex-start">Save Advisor Settings</button>
    </div>
  </details>

  <!-- Not enabled notice -->
  <div id="advisor-disabled-notice" class="config-section" style="display:none">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:16px">
      <div>
        <div style="font-size:13px;font-weight:600;color:var(--text-primary);margin-bottom:4px">Model Advisor is disabled</div>
        <div style="font-size:12px;color:var(--text-tertiary)">Enable it in <code style="font-family:var(--font-mono);color:var(--accent)">guardclaw.json</code> \u2192 <code style="font-family:var(--font-mono)">privacy.modelAdvisor.enabled: true</code></div>
      </div>
    </div>
  </div>

  <!-- Suggestions header -->
  <div id="advisor-header" style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;display:none">
    <div>
      <div style="font-size:14px;font-weight:700;color:var(--text-primary)">Model Suggestions</div>
      <div style="font-size:11px;color:var(--text-tertiary);margin-top:2px" id="advisor-last-checked">Last checked: \u2014</div>
    </div>
    <div style="display:flex;gap:8px">
      <div class="filter-bar" style="margin-bottom:0">
        <button class="filter-btn active" onclick="setAdvisorFilter('pending')">Pending</button>
        <button class="filter-btn" onclick="setAdvisorFilter('accepted')">Accepted</button>
        <button class="filter-btn" onclick="setAdvisorFilter('dismissed')">Dismissed</button>
        <button class="filter-btn" onclick="setAdvisorFilter(null)">All</button>
      </div>
      <button class="btn btn-sm btn-outline" id="advisor-run-btn" onclick="runAdvisor()">Run Check Now</button>
    </div>
  </div>

  <div id="advisor-list"></div>
</div>

<!-- Access Control (Exempt + Banned) -->
<div id="banned-panel" class="panel">

  <!-- Exempt Senders -->
  <div class="config-section" style="margin-bottom:20px">
    <h3 style="color:#8DC63F">Trusted Senders (Exempt from Injection Detection)</h3>
    <p style="font-size:13px;color:var(--text-secondary);margin-bottom:16px">
      Discord user IDs listed here skip the S0 injection scanner entirely. Use this for operators and trusted team members whose messages should never be blocked. Their messages are still subject to S2/S3 privacy routing.<br>
      <span style="font-size:11px;color:var(--text-tertiary);margin-top:4px;display:block">Find your Discord ID: enable Developer Mode in Discord settings \u2192 right-click your name \u2192 Copy User ID.</span>
    </p>
    <div style="display:flex;gap:8px;margin-bottom:14px">
      <input id="exempt-input" type="text" placeholder="Discord user ID (e.g. 1317396442993922061)"
        style="flex:1;padding:10px 14px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:var(--radius-sm);color:var(--text-primary);font-size:13px;font-family:var(--font-mono);outline:none"
        onkeydown="if(event.key==='Enter')addExempt()">
      <button class="btn btn-primary btn-sm" onclick="addExempt()" style="white-space:nowrap">+ Add Trusted</button>
    </div>
    <table class="data-table" id="exempt-table">
      <thead><tr><th>Discord User ID</th><th style="text-align:right">Action</th></tr></thead>
      <tbody id="exempt-body"><tr><td colspan="2" class="empty-state">No trusted senders configured</td></tr></tbody>
    </table>
  </div>

  <!-- Banned Senders -->
  <div class="config-section">
    <h3 style="color:#ef4444">Banned Senders (Auto-blocked)</h3>
    <p style="font-size:13px;color:var(--text-secondary);margin-bottom:14px">Senders automatically banned after 2+ injection attempts. Blocked immediately before any detection runs.</p>
    <table class="data-table" id="banned-table">
      <thead><tr><th>Sender ID</th><th style="text-align:right">Action</th></tr></thead>
      <tbody id="banned-body"><tr><td colspan="2" class="empty-state">No banned senders</td></tr></tbody>
    </table>
  </div>

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

        <!-- S3 Policy -->
        <div class="subsection">
          <h4 data-i18n="priv.s3policy">S3 Policy \u2014 Confidential Content Handling</h4>
          <div class="hint" style="margin-bottom:12px" data-i18n="priv.s3policy_hint">Controls what happens when S3 (confidential) content is detected.</div>
          <div class="field">
            <div style="display:flex;flex-direction:column;gap:10px;">
              <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;">
                <input type="radio" name="s3policy" id="s3policy-local" value="local-only" style="margin-top:3px;" onchange="updateS3PolicyUI()">
                <div>
                  <div style="font-weight:600;" data-i18n="priv.s3policy_local">Local Only (default)</div>
                  <div class="hint" data-i18n="priv.s3policy_local_hint">S3 content stays on device. Routes to local guard agent for reasoning. Requires 64 GB+ or distributed setup.</div>
                </div>
              </label>
              <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;">
                <input type="radio" name="s3policy" id="s3policy-redact" value="redact-and-forward" style="margin-top:3px;" onchange="updateS3PolicyUI()">
                <div>
                  <div style="font-weight:600;">Redact &amp; Forward \u26A0\uFE0F</div>
                  <div class="hint">Strips all credentials &amp; secrets locally, then forwards sanitised content to cloud. Works on 16 GB standalone. Security depends on redaction quality.</div>
                </div>
              </label>
              <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;">
                <input type="radio" name="s3policy" id="s3policy-synthesize" value="synthesize" style="margin-top:3px;" onchange="updateS3PolicyUI()">
                <div>
                  <div style="font-weight:600;">Synthesize (transparent) \u2728</div>
                  <div class="hint">Local model rewrites S3 content into a natural-language description before sending to cloud. Neither the cloud model nor the user sees that interception occurred. Requires local model to be enabled. Falls back to Local Only on failure.</div>
                </div>
              </label>
            </div>
          </div>
          <div id="s3policy-warning" style="display:none;margin-top:10px;padding:10px 14px;background:rgba(255,160,0,0.12);border:1px solid rgba(255,160,0,0.4);border-radius:6px;font-size:12px;color:#ffb347;">
            \u26A0\uFE0F <strong>Redact &amp; Forward</strong> sends sanitised S3 content to your cloud provider. Security depends on redaction quality. Centrase recommends testing with your data before enabling in production.
          </div>
          <!-- Synthesis config panel \u2014 shown only when synthesize is selected -->
          <div id="synthesis-config" style="display:none;margin-top:14px;padding:12px 14px;background:rgba(100,200,255,0.06);border:1px solid rgba(100,200,255,0.2);border-radius:6px;">
            <div style="font-weight:600;margin-bottom:10px;font-size:13px;">Synthesis Settings</div>
            <div class="field">
              <label class="field-label">Fallback on failure</label>
              <select id="cfg-syn-fallback" style="width:200px;background:#1a1a1a;color:#e0e0e0;border:1px solid #444;border-radius:4px;padding:4px 8px;">
                <option value="local-only">Local Only (safe default)</option>
                <option value="block">Block message</option>
              </select>
              <div class="hint">What to do if synthesis fails or local model is unreachable.</div>
            </div>
            <div class="field">
              <label class="field-label">Verify output</label>
              <input type="checkbox" id="cfg-syn-verify" checked>
              <span style="font-size:12px;color:#aaa;margin-left:6px;">Re-run S3 detector on synthesis output before sending (recommended)</span>
            </div>
            <div class="field">
              <label class="field-label">Max retries</label>
              <input type="number" id="cfg-syn-retries" value="2" min="0" max="5" style="width:80px;background:#1a1a1a;color:#e0e0e0;border:1px solid #444;border-radius:4px;padding:4px 8px;">
              <div class="hint">Retry attempts if verification finds S3 content in output. Default: 2.</div>
            </div>
            <div class="field">
              <label class="field-label">Max input chars</label>
              <input type="number" id="cfg-syn-maxchars" value="4000" min="500" max="20000" style="width:100px;background:#1a1a1a;color:#e0e0e0;border:1px solid #444;border-radius:4px;padding:4px 8px;">
              <div class="hint">Truncate S3 content to this length before synthesis to avoid token overruns. Default: 4000.</div>
            </div>
            <div class="field">
              <label class="field-label">Timeout (ms)</label>
              <input type="number" id="cfg-syn-timeout" value="20000" min="5000" max="120000" step="1000" style="width:100px;background:#1a1a1a;color:#e0e0e0;border:1px solid #444;border-radius:4px;padding:4px 8px;">
              <div class="hint">Per-attempt timeout for the local synthesis call. Default: 20000.</div>
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
    <div class="field"><label>Endpoint</label><input id="cfg-lm-endpoint" placeholder="http://localhost:11434"><div class="hint" style="margin-top:4px">Full URL of your local model server \u2014 e.g. Ollama: http://localhost:11434 \xB7 LM Studio: http://localhost:1234 \xB7 vLLM: http://localhost:8000 \xB7 SGLang: http://localhost:30000 \xB7 Remote: http://192.168.1.10:11434</div></div>
    <div class="field"><label>Model</label><div style="display:flex;gap:8px;align-items:center"><input id="cfg-lm-model" placeholder="llama3.2:3b" style="flex:1"><button type="button" onclick="fetchAndPickModel('lm')" style="padding:8px 12px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:var(--radius-sm);color:var(--text-secondary);cursor:pointer;font-size:12px;white-space:nowrap">Browse</button></div></div>
    <div class="field"><label data-i18n="cfg.api_key">API Key</label><input id="cfg-lm-apikey" type="password" placeholder="sk-..."></div>
    <div class="field" id="cfg-lm-module-wrap" style="display:none"><label>Custom Module Path</label><input id="cfg-lm-module" placeholder="./my-provider.js"></div>
  </div>

  <div class="config-section">
    <h3>Prompt Injection Detection (S0) <span class="badge badge-hot">instant</span></h3>
    <div class="hint" style="margin-bottom:14px">Controls the local DeBERTa classifier service running on port 8404. Blocks or sanitises injection attempts before they reach the LLM.</div>
    <div class="form-row">
      <label>Enabled</label>
      <div class="toggle-wrap"><input type="checkbox" id="cfg-inj-enabled" class="toggle"><label for="cfg-inj-enabled" class="toggle-label"></label></div>
    </div>
    <div class="form-row">
      <label>Block Threshold <span class="hint-inline">0\u20131 \u2014 score above this is blocked (default 0.85)</span></label>
      <input type="number" id="cfg-inj-block" min="0" max="1" step="0.01" class="input-sm">
    </div>
    <div class="form-row">
      <label>Sanitise Threshold <span class="hint-inline">0\u20131 \u2014 score above this is sanitised but allowed through (default 0.6)</span></label>
      <input type="number" id="cfg-inj-sanitise" min="0" max="1" step="0.01" class="input-sm">
    </div>
    <div class="form-row">
      <label>Heuristics Only <span class="hint-inline">Skip the DeBERTa model, use pattern matching only (faster, lower accuracy)</span></label>
      <div class="toggle-wrap"><input type="checkbox" id="cfg-inj-heuristics" class="toggle"><label for="cfg-inj-heuristics" class="toggle-label"></label></div>
    </div>
    <div class="form-row">
      <label>DeBERTa Endpoint <span class="hint-inline">Override the classifier service URL (default: http://127.0.0.1:8404)</span></label>
      <input type="text" id="cfg-inj-endpoint" placeholder="http://127.0.0.1:8404" class="input-full">
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
    <div class="field"><label>Model (provider/model)</label><div style="display:flex;gap:8px;align-items:center"><input id="cfg-ga-model" placeholder="ollama-remote/qwen3-coder-next:latest" style="flex:1"><button type="button" onclick="fetchAndPickModel('ga')" style="padding:8px 12px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:var(--radius-sm);color:var(--text-secondary);cursor:pointer;font-size:12px;white-space:nowrap">Browse</button></div><div class="hint" style="margin-top:4px">Format: provider/model-name \u2014 e.g. ollama-server/qwen3.5:35b \xB7 lmstudio-server/qwen3.5-35b</div></div>
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
    <div class="hint" style="margin-bottom:14px">These toggles control which PII patterns are stripped from S2 (proxy) requests before forwarding to the cloud. S3 content is always fully redacted regardless of these settings.</div>
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
    <h3>Local Providers <span class="badge badge-hot">instant</span></h3>
    <div class="field">
      <label>Local Providers</label>
      <div class="tag-list" id="cfg-tags-lp"></div>
      <div class="add-row">
        <input id="cfg-tags-lp-input" placeholder="e.g. ollama" onkeydown="if(event.key==='Enter'){event.preventDefault();addTag('lp')}">
        <button class="btn btn-sm btn-outline" onclick="addTag('lp')">Add</button>
      </div>
      <div class="hint" style="margin-top:6px">Provider IDs treated as local (safe for confidential data). Use the provider name, not a URL \u2014 e.g. ollama, lmstudio, vllm. Must match the provider field in your local model config.</div>
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
    <div style="margin-top:10px;display:flex;gap:8px">
      <button class="btn btn-sm btn-outline" onclick="loadDefaultPricing()">Load Defaults</button>
      <button onclick="fetchOpenRouterPrices()" class="btn btn-outline" id="fetch-prices-btn">Fetch Live Prices (OpenRouter)</button>
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

async function fetchOpenRouterPrices() {
  var btn = document.getElementById('fetch-prices-btn');
  btn.textContent = 'Fetching\u2026'; btn.disabled = true;
  try {
    var r = await fetch(BASE + '/prices/openrouter');
    var data = await r.json();
    if (data.error) { showToast('Could not reach OpenRouter: ' + data.error, true); return; }
    // Update prices for any models already in the pricing table
    var rows = document.querySelectorAll('#pricing-table tbody tr');
    var updated = 0;
    rows.forEach(function(row) {
      var modelCell = row.querySelector('td:first-child');
      if (!modelCell) return;
      var modelId = modelCell.textContent.trim();
      var match = data.models.find(function(m) { return m.id === modelId || m.id.endsWith('/' + modelId); });
      if (match) {
        var inputs = row.querySelectorAll('input[type=number]');
        if (inputs[0] && match.inputPer1M !== null) inputs[0].value = match.inputPer1M.toFixed(4);
        if (inputs[1] && match.outputPer1M !== null) inputs[1].value = match.outputPer1M.toFixed(4);
        updated++;
      }
    });
    showToast(updated > 0 ? 'Updated prices for ' + updated + ' model(s)' : 'No matching models in your pricing table. Add OpenRouter model IDs first.');
  } catch(e) { showToast('Failed to fetch prices', true); }
  finally { btn.textContent = 'Fetch Live Prices (OpenRouter)'; btn.disabled = false; }
}

// \u2500\u2500 Tabs \u2500\u2500
document.querySelectorAll('.tab').forEach(function(t) {
  t.addEventListener('click', function() {
    document.querySelectorAll('.tab').forEach(function(x) { x.classList.remove('active'); });
    document.querySelectorAll('.panel').forEach(function(x) { x.classList.remove('active'); });
    t.classList.add('active');
    document.getElementById(t.dataset.tab + '-panel').classList.add('active');
    // Refresh data for tabs that show live state
    if (t.dataset.tab === 'banned') refreshAccessControl();
    if (t.dataset.tab === 'detections') refreshDetections();
    if (t.dataset.tab === 'advisor') refreshAdvisor();
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
      fetch(BASE + '/synthesis-stats').then(function(r) { return r.json(); }).catch(function() { return {}; }),
    ]);
    var summary = results[0];
    var hourly = results[1];
    var synthStats = results[2] || {};
    if (summary.error) throw new Error(summary.error);

    var lt = summary.lifetime;
    document.getElementById('cloud-tokens').textContent = fmt(lt.cloud.totalTokens);
    document.getElementById('cloud-reqs').textContent = lt.cloud.requestCount + ' ' + 'requests';
    document.getElementById('local-tokens').textContent = fmt(lt.local.totalTokens);
    document.getElementById('local-reqs').textContent = lt.local.requestCount + ' ' + 'requests';
    document.getElementById('proxy-tokens').textContent = fmt(lt.proxy.totalTokens);
    document.getElementById('proxy-reqs').textContent = lt.proxy.requestCount + ' ' + 'requests';

    var total = lt.cloud.totalTokens + lt.local.totalTokens + lt.proxy.totalTokens;
    var prot = lt.local.totalTokens + lt.proxy.totalTokens;
    var rate = total > 0 ? (prot / total * 100).toFixed(1) + '%' : '--';
    document.getElementById('privacy-rate').textContent = rate;
    document.getElementById('privacy-sub').textContent = total > 0
      ? fmt(prot) + ' / ' + fmt(total) + ' ' + 'of total tokens protected'
      : 'No data yet';

    var cloudCost = (lt.cloud.estimatedCost || 0) + (lt.proxy.estimatedCost || 0);
    document.getElementById('cloud-cost').textContent = fmtCost(cloudCost);
    document.getElementById('cloud-cost-sub').textContent = 'estimated cloud API cost';

    document.getElementById('detail-body').innerHTML =
      fillRow('Cloud', lt.cloud) + fillRow('Local', lt.local) + fillRow('Redacted', lt.proxy);

    var bs = summary.bySource || {};
    var routerB = bs.router || {inputTokens:0,outputTokens:0,cacheReadTokens:0,totalTokens:0,requestCount:0};
    var taskB = bs.task || {inputTokens:0,outputTokens:0,cacheReadTokens:0,totalTokens:0,requestCount:0};
    document.getElementById('source-body').innerHTML =
      fillRow('\u{1F500} Router (overhead)', routerB) + fillRow('\u26A1 Task (execution)', taskB);

    var infoHtml = '';
    if (summary.startedAt) infoHtml += 'Uptime: ' + timeAgo(summary.startedAt);
    if (summary.lastUpdatedAt) infoHtml += ' &middot; ' + 'Last activity: ' + timeAgo(summary.lastUpdatedAt);
    document.getElementById('info-bar').innerHTML = infoHtml;

    document.getElementById('status-dot').className = 'status-dot';
    document.getElementById('status-text').textContent = 'Online';
    document.getElementById('last-updated').textContent = 'Updated ' + fmtTime(Date.now());

    updateChart(hourly);
    renderSynthesisStats(synthStats);
  } catch (e) {
    document.getElementById('status-dot').className = 'status-dot err';
    document.getElementById('status-text').textContent = 'Error: ' + (e.message || 'unavailable');
  }
}

function p95(samples) {
  if (!samples || samples.length === 0) return null;
  var sorted = samples.slice().sort(function(a, b) { return a - b; });
  var idx = Math.floor(sorted.length * 0.95);
  return sorted[Math.min(idx, sorted.length - 1)];
}

function fmtMs(ms) {
  if (ms == null) return '\u2014';
  return ms >= 1000 ? (ms / 1000).toFixed(1) + 's' : ms + 'ms';
}

function renderSynthesisStats(syn) {
  var section = document.getElementById('synthesis-stats-section');
  var body = document.getElementById('synthesis-stats-body');
  var sources = ['user_message', 'tool_result'];
  var labels = { user_message: 'User message', tool_result: 'Tool result' };
  var hasData = sources.some(function(s) { return syn[s] && syn[s].count > 0; });

  section.style.display = hasData ? 'block' : 'none';
  if (!hasData) return;

  body.innerHTML = sources.map(function(s) {
    var b = syn[s] || {};
    if (!b.count && !b.failCount) return '';
    var avg = b.count > 0 ? Math.round(b.totalMs / b.count) : null;
    var est = p95(b.recentSamples);
    return '<tr>' +
      '<td>' + labels[s] + '</td>' +
      '<td>' + (b.count || 0) + '</td>' +
      '<td>' + fmtMs(avg) + '</td>' +
      '<td>' + fmtMs(b.minMs) + '</td>' +
      '<td>' + fmtMs(b.maxMs) + '</td>' +
      '<td>' + fmtMs(est) + '</td>' +
      '<td style="color:' + ((b.failCount || 0) > 0 ? '#ff6b6b' : 'inherit') + '">' + (b.failCount || 0) + '</td>' +
      '</tr>';
  }).join('');
}

async function resetStats() {
  if (!confirm('Reset all token statistics? This cannot be undone.')) return;
  try {
    var r = await fetch(BASE + '/reset', { method: 'POST' });
    var body = await r.json();
    if (body.error) throw new Error(body.error);
    showToast('Stats reset successfully');
    refreshStats();
    refreshSessions();
  } catch (e) {
    showToast('Failed to reset stats: ' + (e.message || ''), true);
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
          { label: 'Cloud', data: cloudData, borderColor: '#2563eb', backgroundColor: 'rgba(37,99,235,0.06)', fill: true, tension: 0.4, borderWidth: 2 },
          { label: 'Local', data: localData, borderColor: '#059669', backgroundColor: 'rgba(5,150,105,0.06)', fill: true, tension: 0.4, borderWidth: 2 },
          { label: 'Redacted', data: proxyData, borderColor: '#d97706', backgroundColor: 'rgba(217,119,6,0.06)', fill: true, tension: 0.4, borderWidth: 2 },
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
      tbody.innerHTML = '<tr><td colspan="11" class="empty-state">' + 'No session data yet' + '</td></tr>';
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
      (_detectionFilter !== 'all' ? 'No detections for ' + _detectionFilter : 'No detections yet') + '</td></tr>';
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

// \u2500\u2500 Model Picker \u2500\u2500
async function fetchAndPickModel(target) {
  const endpoint = document.getElementById('cfg-lm-endpoint').value;
  const type = target === 'lm' ? document.getElementById('cfg-lm-type').value : 'openai-compatible';
  const btn = event.target;
  btn.textContent = '\u2026';
  btn.disabled = true;
  try {
    const r = await fetch(BASE + '/models?endpoint=' + encodeURIComponent(endpoint) + '&type=' + encodeURIComponent(type));
    const data = await r.json();
    if (!data.models || data.models.length === 0) { alert('No models found at that endpoint. Is the server running?'); return; }
    const chosen = await showModelPicker(data.models);
    if (!chosen) return;
    const inputId = target === 'lm' ? 'cfg-lm-model' : 'cfg-ga-model';
    document.getElementById(inputId).value = chosen;
  } catch { alert('Could not reach model endpoint.'); }
  finally { btn.textContent = 'Browse'; btn.disabled = false; }
}

function showModelPicker(models) {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1000;display:flex;align-items:center;justify-content:center';
    const box = document.createElement('div');
    box.style.cssText = 'background:#2a2e32;border:1px solid #4a5058;border-radius:12px;padding:20px;min-width:320px;max-width:480px;max-height:60vh;display:flex;flex-direction:column;gap:12px';
    box.innerHTML = \`<div style="font-weight:600;font-size:14px;color:#f0f0f0">Select a model</div><input id="model-picker-filter" placeholder="Filter..." style="background:#3a3f44;border:1px solid #4a5058;border-radius:6px;padding:7px 10px;color:#f0f0f0;font-size:13px;outline:none"><div id="model-picker-list" style="overflow-y:auto;display:flex;flex-direction:column;gap:4px"></div><button onclick="this.closest('div[style*=inset]').remove();window._pickerResolve(null)" style="align-self:flex-end;padding:6px 14px;border-radius:6px;background:#353a3e;border:1px solid #4a5058;color:#a8b0b8;cursor:pointer;font-size:13px">Cancel</button>\`;
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    window._pickerResolve = resolve;
    const list = box.querySelector('#model-picker-list');
    const renderList = (filter) => {
      list.innerHTML = '';
      models.filter(m => m.toLowerCase().includes(filter.toLowerCase())).forEach(m => {
        const btn = document.createElement('button');
        btn.textContent = m;
        btn.style.cssText = 'text-align:left;padding:8px 10px;border-radius:6px;background:#353a3e;border:1px solid #4a5058;color:#f0f0f0;cursor:pointer;font-size:13px';
        btn.onmouseover = () => btn.style.background = '#3a3f44';
        btn.onmouseout = () => btn.style.background = '#353a3e';
        btn.onclick = () => { overlay.remove(); resolve(m); };
        list.appendChild(btn);
      });
    };
    renderList('');
    box.querySelector('#model-picker-filter').oninput = (e) => renderList(e.target.value);
  });
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

    // s3Policy radio
    var s3pol = p.s3Policy || 'local-only';
    var s3Radio = document.querySelector('input[name="s3policy"][value="' + s3pol + '"]');
    if (s3Radio) s3Radio.checked = true;
    updateS3PolicyUI();

    // synthesis config
    var syn = p.synthesis || {};
    var synFallback = document.getElementById('cfg-syn-fallback');
    if (synFallback) synFallback.value = syn.fallback || 'local-only';
    var synVerify = document.getElementById('cfg-syn-verify');
    if (synVerify) synVerify.checked = syn.verifyOutput !== false;
    var synRetries = document.getElementById('cfg-syn-retries');
    if (synRetries) synRetries.value = syn.maxRetries != null ? syn.maxRetries : 2;
    var synChars = document.getElementById('cfg-syn-maxchars');
    if (synChars) synChars.value = syn.maxInputChars || 4000;
    var synTimeout = document.getElementById('cfg-syn-timeout');
    if (synTimeout) synTimeout.value = syn.timeoutMs || 20000;

    document.getElementById('cfg-sess-isolate').checked = sess.isolateGuardHistory !== false;
    document.getElementById('cfg-sess-basedir').value = sess.baseDir || '';

    var rd = p.redaction || {};
    ['internalIp','email','envVar','creditCard','chinesePhone','chineseId','chineseAddress','pin'].forEach(function(k) {
      var el = document.getElementById('cfg-rd-' + k);
      if (el) el.checked = !!rd[k];
    });

    // Injection Detection fields
    var inj = p.injection || {};
    var injEl = document.getElementById('cfg-inj-enabled');
    if (injEl) injEl.checked = inj.enabled !== false;
    var injBlock = document.getElementById('cfg-inj-block');
    if (injBlock) injBlock.value = inj.block_threshold != null ? inj.block_threshold : 0.85;
    var injSan = document.getElementById('cfg-inj-sanitise');
    if (injSan) injSan.value = inj.sanitise_threshold != null ? inj.sanitise_threshold : 0.6;
    var injHeur = document.getElementById('cfg-inj-heuristics');
    if (injHeur) injHeur.checked = !!inj.heuristics_only;
    var injEp = document.getElementById('cfg-inj-endpoint');
    if (injEp) injEp.value = inj.deberta_endpoint || '';

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
  var html = '<option value="">' + '-- Select a preset --' + '</option>';
  if (builtins.length) {
    html += '<optgroup label="' + 'Built-in' + '">';
    builtins.forEach(function(p) {
      var dm = p.defaultModel ? ' [' + p.defaultModel + ']' : '';
      html += '<option value="' + p.id + '"' + (p.id === _activePreset ? ' selected' : '') + '>' + escHtml(p.name) + escHtml(dm) + '</option>';
    });
    html += '</optgroup>';
  }
  if (customs.length) {
    html += '<optgroup label="' + 'Custom' + '">';
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
    infoEl.textContent = 'Default model: ' + preset.defaultModel;
    infoEl.style.display = 'block';
  } else {
    infoEl.style.display = 'none';
  }
}

async function applyPreset() {
  var id = document.getElementById('preset-select').value;
  if (!id) { showToast('Please select a preset first', true); return; }
  var preset = _presets.find(function(p) { return p.id === id; });
  var applyDefaultModel = false;

  if (preset && preset.defaultModel && preset.defaultModel !== _currentDefaultModel) {
    applyDefaultModel = confirm(
      'This preset will also change the default model to ' + preset.defaultModel +
      '. This requires a gateway restart. Apply default model change?'
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
        showToast('Preset applied. Restart gateway for default model change.');
      } else if (result.defaultModelError) {
        showToast('Preset applied' + ' (' + result.defaultModelError + ')', true);
      } else {
        showToast('Preset applied');
      }
      loadConfig();
      loadPresets();
    } else {
      showToast('Save failed: ' + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast('Save failed: ' + e.message, true);
  }
}

async function saveAsPreset() {
  var name = document.getElementById('preset-save-name').value.trim();
  if (!name) { showToast('Please enter a preset name', true); return; }
  try {
    var res = await fetch(BASE + '/presets/save', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name }),
    });
    var result = await res.json();
    if (result.ok) {
      document.getElementById('preset-save-name').value = '';
      showToast('Preset saved');
      loadPresets();
    } else {
      showToast('Save failed: ' + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast('Save failed: ' + e.message, true);
  }
}

async function deletePreset() {
  var id = document.getElementById('preset-select').value;
  if (!id) return;
  if (!confirm('Delete this custom preset?')) return;
  try {
    var res = await fetch(BASE + '/presets/' + encodeURIComponent(id), {
      method: 'DELETE',
    });
    var result = await res.json();
    if (result.ok) {
      showToast('Preset deleted');
      loadPresets();
    } else {
      showToast('Save failed: ' + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast('Save failed: ' + e.message, true);
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
        injection: {
          enabled: document.getElementById('cfg-inj-enabled').checked,
          block_threshold: parseFloat(document.getElementById('cfg-inj-block').value) || 0.85,
          sanitise_threshold: parseFloat(document.getElementById('cfg-inj-sanitise').value) || 0.6,
          heuristics_only: document.getElementById('cfg-inj-heuristics').checked,
          ...(document.getElementById('cfg-inj-endpoint').value ? { deberta_endpoint: document.getElementById('cfg-inj-endpoint').value } : {}),
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
      showToast('Configuration saved');
      loadPresets();
    } else {
      showToast('Save failed: ' + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast('Save failed: ' + e.message, true);
  }
}

function updateS3PolicyUI() {
  var s3PolicyEl = document.querySelector('input[name="s3policy"]:checked');
  var pol = s3PolicyEl ? s3PolicyEl.value : 'local-only';
  var warn = document.getElementById('s3policy-warning');
  var synPanel = document.getElementById('synthesis-config');
  if (warn) warn.style.display = (pol === 'redact-and-forward') ? 'block' : 'none';
  if (synPanel) synPanel.style.display = (pol === 'synthesize') ? 'block' : 'none';
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
  refreshAccessControl();
}

// \u2500\u2500 Access Control (Exempt + Banned) \u2500\u2500

async function refreshAccessControl() {
  try {
    var [exemptData, bannedData] = await Promise.all([
      fetch(BASE + '/exempt').then(function(r) { return r.json(); }),
      fetch(BASE + '/banned').then(function(r) { return r.json(); }),
    ]);

    // Exempt senders
    var exemptBody = document.getElementById('exempt-body');
    if (exemptBody) {
      var exempt = exemptData.exempt || [];
      if (exempt.length === 0) {
        exemptBody.innerHTML = '<tr><td colspan="2" class="empty-state">No trusted senders configured</td></tr>';
      } else {
        exemptBody.innerHTML = exempt.map(function(id) {
          return '<tr><td><span class="session-key">' + escHtml(id) + '</span></td>' +
            '<td style="text-align:right"><button class="btn btn-sm btn-danger" onclick="removeExempt(\\'' + escHtml(id) + '\\')">Remove</button></td></tr>';
        }).join('');
      }
    }

    // Banned senders
    var bannedBody = document.getElementById('banned-body');
    if (bannedBody) {
      var banned = bannedData.banned || [];
      if (banned.length === 0) {
        bannedBody.innerHTML = '<tr><td colspan="2" class="empty-state">No banned senders</td></tr>';
      } else {
        bannedBody.innerHTML = banned.map(function(id) {
          return '<tr><td><span class="session-key">' + escHtml(id) + '</span></td>' +
            '<td style="text-align:right"><button class="btn btn-sm btn-danger" onclick="unbanSender(\\'' + escHtml(id) + '\\')">Unban</button></td></tr>';
        }).join('');
      }
    }
  } catch (e) { /* non-critical */ }
}

// Keep refreshBanned as alias for backward compat
function refreshBanned() { refreshAccessControl(); }

async function addExempt() {
  var input = document.getElementById('exempt-input');
  var senderId = (input.value || '').trim();
  if (!senderId) { showToast('Enter a Discord user ID', true); return; }
  try {
    var res = await fetch(BASE + '/exempt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ senderId: senderId }),
    });
    var result = await res.json();
    if (result.ok) {
      showToast(result.already ? senderId + ' already trusted' : 'Added trusted sender: ' + senderId);
      input.value = '';
      refreshAccessControl();
    } else {
      showToast('Failed: ' + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast('Failed: ' + e.message, true);
  }
}

async function removeExempt(senderId) {
  try {
    var res = await fetch(BASE + '/exempt/' + encodeURIComponent(senderId), { method: 'DELETE' });
    var result = await res.json();
    if (result.ok) {
      showToast('Removed trusted sender: ' + senderId);
      refreshAccessControl();
    } else {
      showToast('Failed: ' + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast('Failed: ' + e.message, true);
  }
}

async function unbanSender(senderId) {
  try {
    var res = await fetch(BASE + '/unban', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ senderId: senderId }),
    });
    var result = await res.json();
    if (result.ok) {
      showToast('Unbanned: ' + senderId);
      refreshAccessControl();
    } else {
      showToast('Unban failed: ' + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast('Unban failed: ' + e.message, true);
  }
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
      showToast('"' + name + '" saved & applied');
      loadPrompts();
    } else {
      showToast('Save failed: ' + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast('Save failed: ' + e.message, true);
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
  if (!msg) { showToast('Enter a test message', true); return; }
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
      showToast('Test failed: ' + data.error, true);
      return;
    }
    document.getElementById('tr-level').innerHTML = '<span class="level-tag level-' + data.level + '">' + data.level + '</span>';
    document.getElementById('tr-action').textContent = data.action || 'passthrough';
    document.getElementById('tr-target').textContent = data.target ? (data.target.provider + '/' + data.target.model) : '(none)';
    document.getElementById('tr-router').textContent = data.routerId || '(none)';
    document.getElementById('tr-reason').textContent = data.reason || '(none)';
    document.getElementById('tr-confidence').textContent = data.confidence != null ? (data.confidence * 100).toFixed(0) + '%' : '-';
    var perEl = document.getElementById('tr-per-router');
    if (data.routers && data.routers.length > 0) {
      var html = '<div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border-subtle)">' +
        '<div style="font-size:11px;text-transform:uppercase;color:var(--text-tertiary);letter-spacing:.06em;font-weight:700;margin-bottom:10px">' + 'Individual Router Results' + '</div>';
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
    showToast('Test failed: ' + e.message, true);
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
    var customBadge = p.isCustom ? '<span class="custom-badge">' + 'customized' + '</span>' : '';
    html += '<div style="margin-bottom:16px">' +
      '<div class="prompt-header">' +
        '<h4>' + escHtml(p.label) + customBadge + '</h4>' +
        '<div class="prompt-actions">' +
          '<button class="btn btn-sm btn-outline" onclick="resetPrompt(\\'' + escHtml(name) + '\\')">' + 'Reset Default' + '</button>' +
          '<button class="btn btn-sm btn-primary" onclick="savePrompt(\\'' + escHtml(name) + '\\')">' + 'Save' + '</button>' +
        '</div>' +
      '</div>' +
      '<textarea class="prompt-editor" id="prompt-' + escHtml(name) + '">' + escHtml(p.content) + '</textarea>' +
    '</div>';
  });
  c.innerHTML = html || '<div style="color:var(--text-tertiary);font-size:13px">' + 'Loading prompts...' + '</div>';
}

// \u2500\u2500 Per-Router Test \u2500\u2500

async function runRouterTest(routerId) {
  var msgEl = document.getElementById('test-' + routerId + '-message');
  var msg = msgEl ? msgEl.value.trim() : '';
  if (!msg) { showToast('Enter a test message', true); return; }
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
      showToast('Test failed: ' + data.error, true);
      return;
    }
    document.getElementById('tr-' + routerId + '-level').innerHTML = '<span class="level-tag level-' + data.level + '">' + data.level + '</span>';
    document.getElementById('tr-' + routerId + '-action').textContent = data.action || 'passthrough';
    document.getElementById('tr-' + routerId + '-target').textContent = data.target ? (data.target.provider + '/' + data.target.model) : '(none)';
    document.getElementById('tr-' + routerId + '-reason').textContent = data.reason || '(none)';
    document.getElementById('tr-' + routerId + '-confidence').textContent = data.confidence != null ? (data.confidence * 100).toFixed(0) + '%' : '-';
    resultEl.classList.add('visible');
  } catch (e) {
    loadingEl.style.display = 'none';
    showToast('Test failed: ' + e.message, true);
  }
}

// \u2500\u2500 Save Privacy Router \u2500\u2500

async function savePrivacyRouter() {
  try {
    var s3PolicyEl = document.querySelector('input[name="s3policy"]:checked');
    var s3Policy = s3PolicyEl ? s3PolicyEl.value : 'local-only';
    var synthesis = undefined;
    if (s3Policy === 'synthesize') {
      synthesis = {
        fallback: document.getElementById('cfg-syn-fallback').value || 'local-only',
        verifyOutput: document.getElementById('cfg-syn-verify').checked,
        maxRetries: parseInt(document.getElementById('cfg-syn-retries').value, 10) || 2,
        maxInputChars: parseInt(document.getElementById('cfg-syn-maxchars').value, 10) || 4000,
        timeoutMs: parseInt(document.getElementById('cfg-syn-timeout').value, 10) || 20000,
      };
    }
    var payload = {
      privacy: {
        enabled: document.getElementById('cfg-privacy-enabled').checked,
        s3Policy: s3Policy,
        synthesis: synthesis,
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
      showToast('Privacy Router saved');
    } else {
      showToast('Save failed: ' + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast('Save failed: ' + e.message, true);
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
      showToast('Cost-Optimizer config saved');
      loadConfig();
    } else {
      showToast('Save failed: ' + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast('Save failed: ' + e.message, true);
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
      showToast('Execution order saved');
    } else {
      showToast('Save failed: ' + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast('Save failed: ' + e.message, true);
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
        '<button class="btn btn-sm btn-danger" style="margin-left:auto" onclick="event.stopPropagation();removeCustomRouter(\\'' + escHtml(id) + '\\')">' + 'Delete' + '</button>' +
      '</div>' +
      '<div class="router-section-body">' +
        '<div class="field-toggle" style="margin-bottom:18px">' +
          '<label>' + 'Enabled' + '</label>' +
          '<label class="toggle"><input type="checkbox" id="cfg-cr-enabled-' + escHtml(id) + '"' + checked + '><span class="slider"></span></label>' +
        '</div>' +

        '<div class="subsection">' +
          '<h4>' + 'Keyword Rules' + '</h4>' +
          '<div class="rules-grid">' +
            '<div class="rules-col">' +
              '<h4>' + 'S2 \u2014 Sensitive Keywords' + '</h4>' +
              '<div class="tag-list" id="cfg-tags-cr-kw-s2-' + escHtml(id) + '"></div>' +
              '<div class="add-row">' +
                '<input id="cfg-tags-cr-kw-s2-' + escHtml(id) + '-input" placeholder="Add S2 keyword" onkeydown="if(event.key===\\'Enter\\'){event.preventDefault();addTag(\\'cr-kw-s2-' + escHtml(id) + '\\')}"><button class="btn btn-sm btn-outline" onclick="addTag(\\'cr-kw-s2-' + escHtml(id) + '\\')">Add</button>' +
              '</div>' +
              '<div style="margin-top:14px"><h4 style="font-size:11px;color:var(--text-tertiary);margin-bottom:8px;text-transform:uppercase;letter-spacing:.06em;font-weight:700">' + 'S2 \u2014 Sensitive Patterns (regex)' + '</h4></div>' +
              '<div class="tag-list" id="cfg-tags-cr-pat-s2-' + escHtml(id) + '"></div>' +
              '<div class="add-row">' +
                '<input id="cfg-tags-cr-pat-s2-' + escHtml(id) + '-input" placeholder="Add S2 pattern" onkeydown="if(event.key===\\'Enter\\'){event.preventDefault();addTag(\\'cr-pat-s2-' + escHtml(id) + '\\')}"><button class="btn btn-sm btn-outline" onclick="addTag(\\'cr-pat-s2-' + escHtml(id) + '\\')">Add</button>' +
              '</div>' +
            '</div>' +
            '<div class="rules-col">' +
              '<h4>' + 'S3 \u2014 Confidential Keywords' + '</h4>' +
              '<div class="tag-list" id="cfg-tags-cr-kw-s3-' + escHtml(id) + '"></div>' +
              '<div class="add-row">' +
                '<input id="cfg-tags-cr-kw-s3-' + escHtml(id) + '-input" placeholder="Add S3 keyword" onkeydown="if(event.key===\\'Enter\\'){event.preventDefault();addTag(\\'cr-kw-s3-' + escHtml(id) + '\\')}"><button class="btn btn-sm btn-outline" onclick="addTag(\\'cr-kw-s3-' + escHtml(id) + '\\')">Add</button>' +
              '</div>' +
              '<div style="margin-top:14px"><h4 style="font-size:11px;color:var(--text-tertiary);margin-bottom:8px;text-transform:uppercase;letter-spacing:.06em;font-weight:700">' + 'S3 \u2014 Confidential Patterns (regex)' + '</h4></div>' +
              '<div class="tag-list" id="cfg-tags-cr-pat-s3-' + escHtml(id) + '"></div>' +
              '<div class="add-row">' +
                '<input id="cfg-tags-cr-pat-s3-' + escHtml(id) + '-input" placeholder="Add S3 pattern" onkeydown="if(event.key===\\'Enter\\'){event.preventDefault();addTag(\\'cr-pat-s3-' + escHtml(id) + '\\')}"><button class="btn btn-sm btn-outline" onclick="addTag(\\'cr-pat-s3-' + escHtml(id) + '\\')">Add</button>' +
              '</div>' +
            '</div>' +
          '</div>' +
        '</div>' +

        '<div class="subsection">' +
          '<h4>' + 'Classification Prompt' + ' <span style="font-size:11px;color:var(--text-tertiary);text-transform:none;letter-spacing:0;font-weight:400">' + '(optional)' + '</span></h4>' +
          '<div class="hint" style="margin-bottom:10px">' + 'If set, the local LLM will classify messages using this prompt. Should output JSON with {level, reason}.' + '</div>' +
          '<textarea class="prompt-editor" id="cr-prompt-' + escHtml(id) + '">' + escHtml(prompt) + '</textarea>' +
        '</div>' +

        '<div class="subsection">' +
          '<h4>' + 'Test' + ' (' + escHtml(id) + ')</h4>' +
          '<textarea class="test-input" id="test-' + escHtml(id) + '-message" placeholder="' + escHtml('Enter a test message') + '..."></textarea>' +
          '<div style="display:flex;gap:8px;margin-top:10px;align-items:center">' +
            '<button class="btn btn-primary btn-sm" onclick="runRouterTest(\\'' + escHtml(id) + '\\')">' + 'Test' + '</button>' +
          '</div>' +
          '<div class="test-result" id="test-' + escHtml(id) + '-result">' +
            '<div class="test-result-row"><span class="test-result-label">' + 'Level' + '</span><span class="test-result-value" id="tr-' + escHtml(id) + '-level">-</span></div>' +
            '<div class="test-result-row"><span class="test-result-label">' + 'Action' + '</span><span class="test-result-value" id="tr-' + escHtml(id) + '-action">-</span></div>' +
            '<div class="test-result-row"><span class="test-result-label">' + 'Target' + '</span><span class="test-result-value" id="tr-' + escHtml(id) + '-target">-</span></div>' +
            '<div class="test-result-row"><span class="test-result-label">' + 'Reason' + '</span><span class="test-result-value" id="tr-' + escHtml(id) + '-reason">-</span></div>' +
            '<div class="test-result-row"><span class="test-result-label">' + 'Confidence' + '</span><span class="test-result-value" id="tr-' + escHtml(id) + '-confidence">-</span></div>' +
          '</div>' +
          '<div class="test-loading" id="test-' + escHtml(id) + '-loading" style="display:none">' + 'Testing...' + '</div>' +
        '</div>' +

        '<div class="save-bar"><button class="btn btn-primary" onclick="saveCustomRouter(\\'' + escHtml(id) + '\\')">' + 'Save' + ' ' + escHtml(id) + '</button></div>' +
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
  if (!id) { showToast('Enter a router ID', true); return; }
  if (_routers[id]) { showToast('"' + id + '" already exists', true); return; }
  _routers[id] = {
    enabled: true,
    type: 'configurable',
    options: { keywords: { S2: [], S3: [] }, patterns: { S2: [], S3: [] }, prompt: '' }
  };
  idInput.value = '';
  renderCustomRouterCards();
  updateAvailableRouters();
  showToast('"' + id + '" created \u2014 configure and save it below');
}

function removeCustomRouter(id) {
  if (!confirm('Delete router "' + id + '"? This cannot be undone.')) return;
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
      showToast('"' + id + '" deleted');
      renderCustomRouterCards();
    } else {
      showToast('Save failed: ' + (result.error || 'unknown'), true);
    }
  }).catch(function(e) {
    showToast('Save failed: ' + e.message, true);
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
      showToast('"' + id + '" saved');
    } else {
      showToast('Save failed: ' + (result.error || 'unknown'), true);
    }
  } catch (e) {
    showToast('Save failed: ' + e.message, true);
  }
}

// \u2500\u2500 Init \u2500\u2500
refreshAll();
loadConfig();
loadPresets();
loadPrompts();
setInterval(refreshAll, 30000);

// \u2500\u2500 Advisor + Budget \u2500\u2500
var _advisorFilter = 'pending';

function setAdvisorFilter(status) {
  _advisorFilter = status;
  document.querySelectorAll('#advisor-header .filter-btn').forEach(function(b) {
    b.classList.remove('active');
    var label = b.textContent.trim().toLowerCase();
    if ((status === null && label === 'all') || label === (status || '')) b.classList.add('active');
  });
  refreshAdvisorList();
}

function refreshAdvisorList() {
  var url = BASE + '/suggestions' + (_advisorFilter ? '?status=' + _advisorFilter : '');
  fetch(url).then(function(r) { return r.json(); }).then(function(data) {
    var list = document.getElementById('advisor-list');
    var lastEl = document.getElementById('advisor-last-checked');
    if (lastEl && data.lastCheckedAt) lastEl.textContent = 'Last checked: ' + new Date(data.lastCheckedAt).toLocaleString();
    var items = data.suggestions || [];

    // Update badge
    var badge = document.getElementById('advisor-badge');
    if (badge) {
      fetch(BASE + '/suggestions?status=pending').then(function(r2) { return r2.json(); }).then(function(d2) {
        var n = (d2.suggestions || []).length;
        badge.style.display = n > 0 ? '' : 'none';
        badge.textContent = n > 0 ? String(n) : '';
      }).catch(function() {});
    }

    if (!items.length) {
      list.innerHTML = '<div class="empty-state">No ' + (_advisorFilter || '') + ' suggestions</div>';
      return;
    }
    list.innerHTML = items.map(renderSuggestion).join('');
  }).catch(function() {
    document.getElementById('advisor-list').innerHTML = '<div class="empty-state">Failed to load suggestions</div>';
  });
}

function renderSuggestion(s) {
  var icons = { openrouter_cheaper: '\u{1F4B8}', openrouter_best_value: '\u2696\uFE0F', openrouter_best: '\u2B50', local_model: '\u{1F5A5}\uFE0F', deberta_update: '\u{1F504}' };
  var categoryColors = { openrouter_cheaper: '#6b7280', openrouter_best_value: '#8b5cf6', openrouter_best: '#f59e0b' };
  var categoryLabels = { openrouter_cheaper: 'CHEAPEST', openrouter_best_value: 'BEST VALUE', openrouter_best: 'TOP PICK' };
  var icon = icons[s.type] || '\u{1F4A1}';
  var catLabel = categoryLabels[s.type]
    ? '<span style="font-size:10px;font-weight:700;letter-spacing:.06em;color:' + (categoryColors[s.type] || 'var(--text-tertiary)') + ';margin-left:8px;vertical-align:middle">' + categoryLabels[s.type] + '</span>'
    : '';
  var saving = s.savingsPercent ? '<span class="saving-pill">-' + s.savingsPercent.toFixed(0) + '%</span>' : '';
  var actions = '';
  if (s.status === 'pending') {
    actions = '<button class="btn btn-sm btn-primary" onclick="acceptSuggestion(\\'' + s.id + '\\',this)">Accept</button>' +
              '<button class="btn btn-sm btn-outline" onclick="dismissSuggestion(\\'' + s.id + '\\')">Dismiss</button>';
  } else {
    actions = '<span style="font-size:11px;color:var(--text-tertiary);padding:8px 0">' + s.status + '</span>';
  }

  var meta = '';
  if (s.currentValue) meta += '<div class="sc-meta-item">Current: <strong>' + esc(s.currentValue) + '</strong></div>';
  if (s.suggestedValue) meta += '<div class="sc-meta-item">Suggested: <strong>' + esc(s.suggestedValue) + '</strong></div>';
  var ctx = s.details && s.details.contextLength;
  if (ctx) meta += '<div class="sc-meta-item">Context: <strong>' + (ctx / 1000).toFixed(0) + 'k</strong></div>';
  if (s.diskRequiredGb) meta += '<div class="sc-meta-item">Disk needed: <strong>' + s.diskRequiredGb.toFixed(1) + ' GB</strong></div>';
  if (s.pullCommand) meta += '<div class="sc-meta-item">Pull: <code>' + esc(s.pullCommand) + '</code></div>';

  var bench = '';
  if (s.benchmarkCurrent && s.benchmarkCandidate) {
    bench = '<div class="sc-bench">' +
      '<div class="sc-bench-col"><div class="sc-bench-label">Current</div>' +
        '<div class="sc-bench-val">' + (s.benchmarkCurrent.jsonSuccessRate * 100).toFixed(0) + '% JSON</div>' +
        '<div style="font-size:11px;color:var(--text-tertiary)">' + Math.round(s.benchmarkCurrent.avgLatencyMs) + 'ms avg</div>' +
      '</div>' +
      '<div class="sc-bench-col"><div class="sc-bench-label">Candidate</div>' +
        '<div class="sc-bench-val">' + (s.benchmarkCandidate.jsonSuccessRate * 100).toFixed(0) + '% JSON</div>' +
        '<div style="font-size:11px;color:var(--text-tertiary)">' + Math.round(s.benchmarkCandidate.avgLatencyMs) + 'ms avg</div>' +
      '</div>' +
    '</div>';
  }

  return '<div class="suggestion-card ' + s.status + '">' +
    '<div class="sc-head">' +
      '<div class="sc-icon">' + icon + '</div>' +
      '<div style="min-width:0;flex:1">' +
        '<div class="sc-title">' + esc(s.title) + catLabel + saving + '</div>' +
        '<div class="sc-desc">' + esc(s.description) + '</div>' +
      '</div>' +
      '<div class="sc-actions">' + actions + '</div>' +
    '</div>' +
    (meta ? '<div class="sc-meta">' + meta + '</div>' : '') +
    bench +
  '</div>';
}

function acceptSuggestion(id, btn) {
  btn.disabled = true;
  btn.textContent = 'Applying\u2026';
  fetch(BASE + '/suggestions/' + id + '/accept', { method: 'POST' })
    .then(function(r) { return r.json(); })
    .then(function(result) {
      if (result.ok) {
        showToast('Suggestion applied \u2014 config updated');
        refreshAdvisorList();
      } else {
        showToast('Failed: ' + (result.message || 'unknown error'), true);
        btn.disabled = false; btn.textContent = 'Accept';
      }
    }).catch(function(e) {
      showToast('Error: ' + e.message, true);
      btn.disabled = false; btn.textContent = 'Accept';
    });
}

function dismissSuggestion(id) {
  fetch(BASE + '/suggestions/' + id + '/dismiss', { method: 'POST' })
    .then(function() { refreshAdvisorList(); })
    .catch(function() {});
}

function runAdvisor() {
  var btn = document.getElementById('advisor-run-btn');
  btn.disabled = true; btn.textContent = 'Checking\u2026';
  fetch(BASE + '/advisor/run', { method: 'POST' })
    .then(function(r) { return r.json(); })
    .then(function() {
      showToast('Advisor check started \u2014 results will appear shortly');
      setTimeout(function() {
        btn.disabled = false; btn.textContent = 'Run Check Now';
        refreshAdvisorList();
      }, 8000);
    }).catch(function() {
      btn.disabled = false; btn.textContent = 'Run Check Now';
    });
}

function refreshBudget() {
  fetch(BASE + '/budget').then(function(r) { return r.json(); }).then(function(b) {
    var section = document.getElementById('budget-section');
    if (!b.enabled) { section.style.display = 'none'; return; }
    section.style.display = '';

    var fmtMoney = function(v) { return v == null ? '\u2014' : '$' + v.toFixed(2); };
    var pct = function(cost, cap) { return cap ? Math.min(100, (cost / cap) * 100) : 0; };

    document.getElementById('budget-daily-cost').textContent = fmtMoney(b.dailyCost);
    document.getElementById('budget-daily-cap').textContent = b.dailyCap ? 'cap: $' + b.dailyCap.toFixed(2) : 'no cap';
    var dailyPct = pct(b.dailyCost, b.dailyCap);
    var dailyBar = document.getElementById('budget-daily-bar');
    dailyBar.style.width = dailyPct + '%';
    dailyBar.style.background = dailyPct >= 100 ? '#ef4444' : dailyPct >= (b.warnAt || 80) ? '#f59e0b' : 'var(--accent)';

    document.getElementById('budget-monthly-cost').textContent = fmtMoney(b.monthlyCost);
    document.getElementById('budget-monthly-cap').textContent = b.monthlyCap ? 'cap: $' + b.monthlyCap.toFixed(2) : 'no cap';
    var monthlyPct = pct(b.monthlyCost, b.monthlyCap);
    var monthlyBar = document.getElementById('budget-monthly-bar');
    monthlyBar.style.width = monthlyPct + '%';
    monthlyBar.style.background = monthlyPct >= 100 ? '#ef4444' : monthlyPct >= (b.warnAt || 80) ? '#f59e0b' : 'var(--accent)';

    document.getElementById('budget-action-label').textContent = 'Action on exceed: ' + b.action;
    // Populate budget inputs
    var budgetDaily = document.getElementById('cfg-budget-daily');
    if (budgetDaily && b.dailyCap != null) budgetDaily.value = b.dailyCap;
    var budgetMonthly = document.getElementById('cfg-budget-monthly');
    if (budgetMonthly && b.monthlyCap != null) budgetMonthly.value = b.monthlyCap;
    var budgetWarn = document.getElementById('cfg-budget-warn');
    if (budgetWarn) budgetWarn.value = b.warnAt || 80;
    var budgetAction = document.getElementById('cfg-budget-action');
    if (budgetAction) budgetAction.value = b.action || 'warn';
  }).catch(function() {});
}

async function saveBudgetSettings() {
  var daily = parseFloat(document.getElementById('cfg-budget-daily').value);
  var monthly = parseFloat(document.getElementById('cfg-budget-monthly').value);
  var payload = {
    privacy: {
      budget: {
        enabled: true,
        dailyCap: isNaN(daily) ? null : daily,
        monthlyCap: isNaN(monthly) ? null : monthly,
        warnAt: parseInt(document.getElementById('cfg-budget-warn').value) || 80,
        action: document.getElementById('cfg-budget-action').value,
      }
    }
  };
  var r = await fetch(BASE + '/config', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  var d = await r.json();
  if (d.ok) { showToast('Budget saved'); refreshBudget(); }
  else showToast('Save failed: ' + d.error, true);
}

async function saveAdvisorSettings() {
  var payload = {
    privacy: {
      modelAdvisor: {
        enabled: document.getElementById('cfg-adv-enabled').checked,
        checkIntervalWeeks: parseInt(document.getElementById('cfg-adv-interval').value) || 2,
        minSavingsPercent: parseInt(document.getElementById('cfg-adv-savings').value) || 20,
        minDiskSpaceGb: parseInt(document.getElementById('cfg-adv-disk').value) || 10,
        openrouterApiKey: document.getElementById('cfg-adv-orkey').value || undefined,
        openrouter: { enabled: document.getElementById('cfg-adv-or').checked },
        llmfit: { enabled: document.getElementById('cfg-adv-llmfit').checked },
        deberta: {
          enabled: document.getElementById('cfg-adv-deberta').checked,
          autoUpdate: document.getElementById('cfg-adv-autoupdate').checked,
        },
      }
    }
  };
  var r = await fetch(BASE + '/config', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
  var d = await r.json();
  if (d.ok) showToast('Advisor settings saved');
  else showToast('Save failed: ' + d.error, true);
}

function refreshAdvisor() {
  refreshBudget();
  // Check if advisor is enabled by fetching config
  fetch(BASE + '/config').then(function(r) { return r.json(); }).then(function(cfg) {
    var ma = (cfg.privacy && cfg.privacy.modelAdvisor) || {};
    var enabled = !!ma.enabled;
    document.getElementById('advisor-disabled-notice').style.display = enabled ? 'none' : '';
    document.getElementById('advisor-header').style.display = enabled ? 'flex' : 'none';
    if (enabled) refreshAdvisorList();
    else document.getElementById('advisor-list').innerHTML = '';
    // Populate advisor settings form
    var advEnabled = document.getElementById('cfg-adv-enabled');
    if (advEnabled) advEnabled.checked = !!ma.enabled;
    var advInterval = document.getElementById('cfg-adv-interval');
    if (advInterval) advInterval.value = ma.checkIntervalWeeks || 2;
    var advSavings = document.getElementById('cfg-adv-savings');
    if (advSavings) advSavings.value = ma.minSavingsPercent || 20;
    var advDisk = document.getElementById('cfg-adv-disk');
    if (advDisk) advDisk.value = ma.minDiskSpaceGb || 10;
    var advOrkey = document.getElementById('cfg-adv-orkey');
    if (advOrkey) advOrkey.value = ma.openrouterApiKey || '';
    var advOr = document.getElementById('cfg-adv-or');
    if (advOr) advOr.checked = !ma.openrouter || ma.openrouter.enabled !== false;
    var advLlmfit = document.getElementById('cfg-adv-llmfit');
    if (advLlmfit) advLlmfit.checked = !ma.llmfit || ma.llmfit.enabled !== false;
    var advDeberta = document.getElementById('cfg-adv-deberta');
    if (advDeberta) advDeberta.checked = !ma.deberta || ma.deberta.enabled !== false;
    var advAutoupdate = document.getElementById('cfg-adv-autoupdate');
    if (advAutoupdate) advAutoupdate.checked = !ma.deberta || ma.deberta.autoUpdate !== false;
    // Also populate budget fields if available
    var budget = (cfg.privacy && cfg.privacy.budget) || {};
    var budgetDaily = document.getElementById('cfg-budget-daily');
    if (budgetDaily && budget.dailyCap != null) budgetDaily.value = budget.dailyCap;
    var budgetMonthly = document.getElementById('cfg-budget-monthly');
    if (budgetMonthly && budget.monthlyCap != null) budgetMonthly.value = budget.monthlyCap;
    var budgetWarn = document.getElementById('cfg-budget-warn');
    if (budgetWarn) budgetWarn.value = budget.warnAt || 80;
    var budgetAction = document.getElementById('cfg-budget-action');
    if (budgetAction) budgetAction.value = budget.action || 'warn';
  }).catch(function() {
    document.getElementById('advisor-disabled-notice').style.display = '';
    document.getElementById('advisor-header').style.display = 'none';
  });
}

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>`;
}

// index.ts
var OPENCLAW_DIR2 = join12(process.env.HOME ?? "/tmp", ".openclaw");
var GUARDCLAW_CONFIG_PATH3 = join12(OPENCLAW_DIR2, "guardclaw.json");
var LEGACY_DASHBOARD_PATH = join12(OPENCLAW_DIR2, "guardclaw-dashboard.json");
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
    join12(OPENCLAW_DIR2, "agents", "main", "agent", "auth-profiles.json")
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
        const apiKeyStr = typeof apiKey === "string" ? apiKey : JSON.stringify(apiKey);
        api.logger.info(`[GuardClaw] Default proxy target: ${defaultProvider} (key: ${apiKeyStr.slice(0, 8)}\u2026)`);
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
    loadInjectionAttemptCounts().catch(() => {
    });
    const userInjection = resolvedPluginConfig.privacy?.injection ?? {};
    const injectionConfig = { ...defaultInjectionConfig, ...userInjection };
    initInjectionConfig(injectionConfig);
    if (injectionConfig.enabled !== false && !injectionConfig.heuristics_only) {
      runDebertaClassifier("test").catch(() => {
      });
    }
    api.logger.info(`[GuardClaw] S0 injection detection initialized (heuristics_only=${injectionConfig.heuristics_only ?? false})`);
    const statsPath = join12(process.env.HOME ?? "/tmp", ".openclaw", "guardclaw-stats.json");
    const collector = new TokenStatsCollector(statsPath);
    setGlobalCollector(collector);
    collector.load().then(() => {
      collector.startAutoFlush();
      api.logger.info(`[GuardClaw] Token stats initialized (${statsPath})`);
    }).catch((err) => {
      api.logger.error(`[GuardClaw] Failed to load token stats: ${String(err)}`);
    });
    loadBudgetData().catch(() => {
    });
    const advisorConfig = resolvedPluginConfig.privacy?.modelAdvisor;
    if (advisorConfig?.enabled) {
      const openrouterKey = advisorConfig.openrouterApiKey || readApiKeyFromAuthProfiles("openrouter");
      initModelAdvisor(advisorConfig, openrouterKey, api.logger).catch((err) => {
        api.logger.warn(`[GuardClaw] Model advisor init failed: ${String(err)}`);
      });
    }
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
