/**
 * GuardClaw Types
 *
 * Core type definitions for the GuardClaw plugin.
 */

export type SensitivityLevel = "S1" | "S2" | "S3";

export type SensitivityLevelNumeric = 1 | 2 | 3;

export type DetectorType = "ruleDetector" | "localModelDetector";

export type Checkpoint = "onUserMessage" | "onToolCallProposed" | "onToolCallExecuted";

/**
 * Edge provider API protocol type.
 *   - "openai-compatible": POST /v1/chat/completions (Ollama, vLLM, LiteLLM, LocalAI, LMStudio, SGLang …)
 *   - "ollama-native":     POST /api/chat (Ollama native API, supports streaming natively)
 *   - "custom":            User-supplied module exporting a callChat function
 */
export type EdgeProviderType = "openai-compatible" | "ollama-native" | "custom";

export type PrivacyConfig = {
  enabled?: boolean;
  /** S2 handling: "proxy" strips PII via local HTTP proxy (default), "local" routes to local model */
  s2Policy?: "proxy" | "local";
  /**
   * S3 handling policy:
   *   "local-only"        — route entirely to guard agent, cloud never sees content (default, safest)
   *   "redact-and-forward" — strip secrets locally then forward to cloud (16 GB deployments)
   *   "synthesize"        — local model processes S3 content and produces a natural-language
   *                         description; cloud model receives the description seamlessly.
   *                         Neither the cloud model nor the user sees that interception occurred.
   */
  s3Policy?: "local-only" | "redact-and-forward" | "synthesize";
  /** Port for the privacy proxy server (default: 8403) */
  proxyPort?: number;
  /** Fine-grained options for s3Policy: "synthesize". Ignored for other policies. */
  synthesis?: SynthesisConfig;
  checkpoints?: {
    onUserMessage?: DetectorType[];
    onToolCallProposed?: DetectorType[];
    onToolCallExecuted?: DetectorType[];
  };
  rules?: {
    keywords?: {
      S2?: string[];
      S3?: string[];
    };
    /** Regex patterns for matching sensitive content (strings are compiled to RegExp) */
    patterns?: {
      S2?: string[];
      S3?: string[];
    };
    tools?: {
      S2?: {
        tools?: string[];
        paths?: string[];
      };
      S3?: {
        tools?: string[];
        paths?: string[];
      };
    };
  };
  localModel?: {
    enabled?: boolean;
    /** API protocol type (default: "openai-compatible") */
    type?: EdgeProviderType;
    /** Provider name for OpenClaw routing (e.g. "ollama", "vllm", "lmstudio") */
    provider?: string;
    model?: string;
    endpoint?: string;
    apiKey?: string;
    /** Path to custom provider module (type="custom" only). Must export callChat(). */
    module?: string;
  };
  guardAgent?: {
    id?: string;
    workspace?: string;
    /** Full model reference in "provider/model" format (e.g. "ollama/llama3.2:3b", "vllm/qwen2.5:7b") */
    model?: string;
  };
  session?: {
    isolateGuardHistory?: boolean;
    /** Base directory for session histories (default: ~/.openclaw) */
    baseDir?: string;
    /**
     * Inject full-track conversation history as context when routing to
     * local models (S3 / S2-local). This replaces the sanitized placeholders
     * ("🔒 [Private content]") with actual previous sensitive interactions
     * so the local model has full conversational context.
     * Default: true (when isolateGuardHistory is true)
     */
    injectDualHistory?: boolean;
    /** Max number of messages to inject from dual-track history (default: 20) */
    historyLimit?: number;
  };
  /**
   * Additional provider names to treat as "local" (safe for S3 routing).
   * Built-in local providers: ollama, llama.cpp, localai, llamafile, lmstudio, vllm, mlx, sglang, tgi.
   * Add custom entries here if you run your own inference backend.
   */
  localProviders?: string[];
  /**
   * Tool names exempt from privacy pipeline detection and PII redaction.
   * Default: empty (no tools are exempt). Users can opt-in via config.
   */
  toolAllowlist?: string[];
  /**
   * Per-model pricing for cloud API cost estimation (USD per 1M tokens).
   * Keys are model name strings; lookup tries exact match, then substring match.
   */
  modelPricing?: Record<string, {
    inputPer1M?: number;
    outputPer1M?: number;
  }>;
  /**
   * Toggle high-false-positive redaction rules individually.
   * All default to false (off) to avoid over-redaction.
   */
  redaction?: RedactionOptions;
  /**
   * Outbound webhook notifications for security events.
   * Supports Discord (rich embeds), Slack (blocks), and generic JSON.
   * Fire-and-forget — never blocks the main request path.
   */
  webhooks?: WebhookConfig[];
  /**
   * Scan LLM responses for accidentally echoed secrets or PII.
   * Runs synchronously in before_message_write — can redact or block.
   */
  responseScanning?: ResponseScanConfig;
  /**
   * Daily and monthly cloud spend caps.
   * Tracks cost independently of token-stats for fast threshold checks.
   */
  budget?: BudgetConfig;
  /** User IDs exempt from outbound message redaction */
  operatorPassthrough?: string[];
  /** Value-based taint tracking for secrets across tool results. */
  taintTracking?: TaintTrackingConfig;
  /**
   * Emit verbose per-request info logs (routing decisions, S0 details, proxy
   * lifecycle). Disabled by default to prevent gateway.log flooding.
   * Enable via guardclaw.json → privacy.debugLogging: true for troubleshooting.
   */
  debugLogging?: boolean;
  /**
   * Use regex-only desensitization for S2 messages instead of the two-step
   * LLM extraction. Saves ~1-2s per message at the cost of missing semantic
   * PII that has no regex pattern (e.g. names in context, freeform addresses).
   * The proxy's defense-in-depth regex still runs regardless.
   * Default: false.
   */
  fastS2?: boolean;
  /**
   * Channel IDs pre-classified as S2. Messages from these channels skip the
   * LLM classification step entirely and go straight to desensitization + proxy.
   * Combined with fastS2, this reduces S2 overhead from ~2s to ~5ms.
   * Channels are auto-added when first LLM-classified as S2 (auto-learn).
   */
  s2Channels?: string[];
};

export type TaintTrackingConfig = {
  /**
   * Enable value-based taint tracking for secrets.
   * When enabled, values read from secrets mounts (/run/secrets/) or detected
   * in S2/S3 tool results are tracked and redacted from all subsequent tool
   * results before they reach the cloud LLM. Default: true.
   */
  enabled?: boolean;
  /**
   * Minimum value length to register as a taint.
   * Shorter values have high false-positive rates (e.g. "ok", "true").
   * Default: 8.
   */
  minValueLength?: number;
  /**
   * Also register S2-level tool result content as tainted, not just S3.
   * Disabled by default to avoid over-redaction; enable for high-sensitivity
   * deployments where S2 content must also be kept out of future LLM context.
   * Default: false.
   */
  trackS2?: boolean;
};

export type InjectionConfig = {
  /** Enable S0 injection detection. Default: true */
  enabled?: boolean;
  /** Skip ML model, use heuristics only (faster but less accurate). Default: false */
  heuristics_only?: boolean;
  /** Score threshold for blocking (0-100, default 70) */
  block_threshold?: number;
  /** Score threshold for sanitising (0-100, default 30) */
  sanitise_threshold?: number;
  /** Discord channel ID for block alerts */
  alert_channel?: string;
  /** Source types exempt from scanning (e.g. ["file"] to trust local files) */
  exempt_sources?: string[];
  /** Discord user IDs exempt from scanning */
  exempt_senders?: string[];
  /** Discord user IDs that are permanently banned (auto-blocked before detection) */
  banned_senders?: string[];
};

export type WebhookFormat = "json" | "discord" | "slack";

export type WebhookEvent =
  | "s3_detected"
  | "s2_detected"
  | "injection_blocked"
  | "ban_triggered"
  | "budget_warning"
  | "budget_exceeded"
  | "response_scan_hit";

export type WebhookConfig = {
  url: string;
  format?: WebhookFormat;
  events?: WebhookEvent[];
  secret?: string;
};

export type ResponseScanAction = "warn" | "redact" | "block";

export type ResponseScanConfig = {
  enabled?: boolean;
  action?: ResponseScanAction;
  scanSecrets?: boolean;
  scanPii?: boolean;
};

export type BudgetAction = "warn" | "pause_cloud" | "block";

export type BudgetConfig = {
  enabled?: boolean;
  dailyCap?: number;
  monthlyCap?: number;
  action?: BudgetAction;
  warnAt?: number;
};

// ── Model Advisor Types ─────────────────────────────────────────────────

export type SuggestionType =
  | "openrouter_cheaper"
  | "openrouter_best_value"
  | "openrouter_best"
  | "local_model"
  | "deberta_update";

export type SuggestionStatus = "pending" | "accepted" | "dismissed";

export type BenchmarkResult = {
  jsonSuccessRate: number; // 0–1
  avgLatencyMs: number;
  runs: number;
};

export type ModelSuggestion = {
  id: string;
  type: SuggestionType;
  status: SuggestionStatus;
  createdAt: string;
  title: string;
  description: string;
  currentValue?: string;
  suggestedValue?: string;
  savingsPercent?: number;
  benchmarkCurrent?: BenchmarkResult;
  benchmarkCandidate?: BenchmarkResult;
  diskRequiredGb?: number;
  pullCommand?: string;
  details?: Record<string, unknown>;
};

export type ModelAdvisorConfig = {
  /** Enable the advisor. Default: false */
  enabled?: boolean;
  /** How often to run checks (weeks). Default: 2 */
  checkIntervalWeeks?: number;
  /** Minimum % cheaper a model must be to warrant a suggestion. Default: 20 */
  minSavingsPercent?: number;
  /** Minimum free disk space (GB) required before suggesting a local model pull. Default: 10 */
  minDiskSpaceGb?: number;
  /** Override the OpenRouter API key (defaults to provider config) */
  openrouterApiKey?: string;
  openrouter?: { enabled?: boolean };
  llmfit?: { enabled?: boolean };
  deberta?: {
    enabled?: boolean;
    /**
     * Automatically apply DeBERTa updates without user confirmation.
     * The config is patched immediately; the new model is downloaded on next
     * injection-service restart. Default: true.
     */
    autoUpdate?: boolean;
  };
  benchmark?: {
    enabled?: boolean;
    runs?: number;
  };
};

/**
 * Configuration for the transparent S3 synthesis pipeline.
 * Only relevant when s3Policy is "synthesize".
 */
export type SynthesisConfig = {
  /**
   * What to do when synthesis fails (local model unavailable, timeout, verification fails).
   * "local-only" — fall back to guard agent routing (safe default)
   * "block"      — block the message entirely and tell the user to retry
   * Default: "local-only"
   */
  fallback?: "local-only" | "block";
  /**
   * Re-run the S3 detector on synthesis output before sending to cloud.
   * If S3 is still detected, retry up to maxRetries times.
   * Default: true (strongly recommended)
   */
  verifyOutput?: boolean;
  /** Max retries if verification fails. Default: 2 */
  maxRetries?: number;
  /** Truncate S3 input to this many characters before synthesis to avoid token overruns. Default: 4000 */
  maxInputChars?: number;
  /** Timeout per synthesis call in milliseconds. Default: 20000 */
  timeoutMs?: number;
};

export type RedactionOptions = {
  /** Internal IP addresses (10.x, 172.16-31.x, 192.168.x). Default: false */
  internalIp?: boolean;
  /** Email addresses. Default: false */
  email?: boolean;
  /** .env file content (KEY=VALUE lines). Default: false */
  envVar?: boolean;
  /** Credit card number pattern (13-19 digits). Default: false */
  creditCard?: boolean;
  /** Chinese mobile phone number (1[3-9]x 11 digits). Default: false */
  chinesePhone?: boolean;
  /** Chinese ID card number (18 digits / 17+X). Default: false */
  chineseId?: boolean;
  /** Chinese address patterns (省/市/区/路/号 etc.). Default: false */
  chineseAddress?: boolean;
  /** PIN / pin code contextual rule. Default: false */
  pin?: boolean;
};

export type DetectionContext = {
  checkpoint: Checkpoint;
  message?: string;
  toolName?: string;
  toolParams?: Record<string, unknown>;
  toolResult?: unknown;
  sessionKey?: string;
  agentId?: string;
  recentContext?: string[];
  /** When true, routers should skip the `enabled` check (dry-run from dashboard). */
  dryRun?: boolean;
};

export type DetectionResult = {
  level: SensitivityLevel;
  levelNumeric: SensitivityLevelNumeric;
  reason?: string;
  detectorType: DetectorType;
  confidence?: number;
};

// ── Router Pipeline Types ───────────────────────────────────────────────

export type RouterAction = "passthrough" | "redirect" | "transform" | "block";

export type RouterDecision = {
  level: SensitivityLevel;
  action?: RouterAction;
  target?: { provider: string; model: string };
  /** When action is "transform", the transformed prompt content */
  transformedContent?: string;
  reason?: string;
  confidence?: number;
  routerId?: string;
};

/**
 * Interface for pluggable routers.
 * The built-in "privacy" router wraps the existing detector + desensitization logic.
 * Users can implement custom routers (cost optimization, content filtering, etc.)
 * and register them in the pipeline config.
 */
export interface GuardClawRouter {
  id: string;
  detect(
    context: DetectionContext,
    config: Record<string, unknown>,
  ): Promise<RouterDecision>;
}

export type RouterRegistration = {
  enabled?: boolean;
  /** "builtin" for privacy/rules, "custom" for user modules, "configurable" for dashboard-created */
  type?: "builtin" | "custom" | "configurable";
  /** Path to custom router module (type="custom" only) */
  module?: string;
  /** Arbitrary config passed to the router's detect() */
  options?: Record<string, unknown>;
  /**
   * Merge weight (0–100, default 50). Higher weight wins when multiple routers
   * produce non-passthrough decisions at the same sensitivity level.
   * Safety routers (privacy) should use high weights; optimization routers
   * (token-saver) should use lower weights so they only take effect when
   * safety routers pass through.
   */
  weight?: number;
};

export type PipelineConfig = {
  onUserMessage?: string[];
  onToolCallProposed?: string[];
  onToolCallExecuted?: string[];
};

// ── Session / History Types ─────────────────────────────────────────────

export type SessionPrivacyState = {
  sessionKey: string;
  /** @deprecated Replaced by per-turn currentTurnLevel. Kept for backward compat. */
  isPrivate: boolean;
  highestLevel: SensitivityLevel;
  /** Highest sensitivity level detected in the CURRENT turn (reset each turn). */
  currentTurnLevel: SensitivityLevel;
  detectionHistory: Array<{
    timestamp: number;
    level: SensitivityLevel;
    checkpoint: Checkpoint;
    reason?: string;
  }>;
};

export function levelToNumeric(level: SensitivityLevel): SensitivityLevelNumeric {
  switch (level) {
    case "S1":
      return 1;
    case "S2":
      return 2;
    case "S3":
      return 3;
  }
}

export function numericToLevel(numeric: SensitivityLevelNumeric): SensitivityLevel {
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

export function maxLevel(...levels: SensitivityLevel[]): SensitivityLevel {
  if (levels.length === 0) return "S1";
  const numeric = levels.map(levelToNumeric);
  const max = Math.max(...numeric) as SensitivityLevelNumeric;
  return numericToLevel(max);
}
