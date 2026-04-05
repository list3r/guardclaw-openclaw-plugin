/**
 * GuardClaw Config Schema
 *
 * Configuration schema for the GuardClaw plugin using TypeBox.
 */

import { Type } from "@sinclair/typebox";

export const guardClawConfigSchema = Type.Object({
  injection: Type.Optional(
    Type.Object({
      enabled: Type.Optional(Type.Boolean()),
      heuristics_only: Type.Optional(Type.Boolean()),
      block_threshold: Type.Optional(Type.Number()),
      sanitise_threshold: Type.Optional(Type.Number()),
      alert_channel: Type.Optional(Type.String()),
      exempt_sources: Type.Optional(Type.Array(Type.String())),
      exempt_senders: Type.Optional(Type.Array(Type.String())),
      banned_senders: Type.Optional(Type.Array(Type.String())),
    }),
  ),
  privacy: Type.Optional(
    Type.Object({
      enabled: Type.Optional(Type.Boolean()),
      s2Policy: Type.Optional(
        Type.Union([Type.Literal("proxy"), Type.Literal("local")]),
      ),
      s3Policy: Type.Optional(
        Type.Union([
          Type.Literal("local-only"),
          Type.Literal("redact-and-forward"),
          Type.Literal("synthesize"),
        ]),
      ),
      synthesis: Type.Optional(
        Type.Object({
          fallback: Type.Optional(Type.Union([Type.Literal("local-only"), Type.Literal("block")])),
          verifyOutput: Type.Optional(Type.Boolean()),
          maxRetries: Type.Optional(Type.Number()),
          maxInputChars: Type.Optional(Type.Number()),
          timeoutMs: Type.Optional(Type.Number()),
        }),
      ),
      proxyPort: Type.Optional(Type.Number()),
      checkpoints: Type.Optional(
        Type.Object({
          onUserMessage: Type.Optional(
            Type.Array(
              Type.Union([Type.Literal("ruleDetector"), Type.Literal("localModelDetector")]),
            ),
          ),
          onToolCallProposed: Type.Optional(
            Type.Array(
              Type.Union([Type.Literal("ruleDetector"), Type.Literal("localModelDetector")]),
            ),
          ),
          onToolCallExecuted: Type.Optional(
            Type.Array(
              Type.Union([Type.Literal("ruleDetector"), Type.Literal("localModelDetector")]),
            ),
          ),
        }),
      ),
      rules: Type.Optional(
        Type.Object({
          keywords: Type.Optional(
            Type.Object({
              S2: Type.Optional(Type.Array(Type.String())),
              S3: Type.Optional(Type.Array(Type.String())),
            }),
          ),
          patterns: Type.Optional(
            Type.Object({
              S2: Type.Optional(Type.Array(Type.String())),
              S3: Type.Optional(Type.Array(Type.String())),
            }),
          ),
          tools: Type.Optional(
            Type.Object({
              S2: Type.Optional(
                Type.Object({
                  tools: Type.Optional(Type.Array(Type.String())),
                  paths: Type.Optional(Type.Array(Type.String())),
                }),
              ),
              S3: Type.Optional(
                Type.Object({
                  tools: Type.Optional(Type.Array(Type.String())),
                  paths: Type.Optional(Type.Array(Type.String())),
                }),
              ),
            }),
          ),
        }),
      ),
      localModel: Type.Optional(
        Type.Object({
          enabled: Type.Optional(Type.Boolean()),
          type: Type.Optional(
            Type.Union([
              Type.Literal("openai-compatible"),
              Type.Literal("ollama-native"),
              Type.Literal("custom"),
            ]),
          ),
          provider: Type.Optional(Type.String()),
          model: Type.Optional(Type.String()),
          endpoint: Type.Optional(Type.String()),
          apiKey: Type.Optional(Type.String()),
          module: Type.Optional(Type.String()),
        }),
      ),
      guardAgent: Type.Optional(
        Type.Object({
          id: Type.Optional(Type.String()),
          workspace: Type.Optional(Type.String()),
          model: Type.Optional(Type.String()),
        }),
      ),
      localProviders: Type.Optional(Type.Array(Type.String())),
      toolAllowlist: Type.Optional(Type.Array(Type.String())),
      modelPricing: Type.Optional(
        Type.Record(
          Type.String(),
          Type.Object({
            inputPer1M: Type.Optional(Type.Number()),
            outputPer1M: Type.Optional(Type.Number()),
          }),
        ),
      ),
      session: Type.Optional(
        Type.Object({
          isolateGuardHistory: Type.Optional(Type.Boolean()),
          baseDir: Type.Optional(Type.String()),
          injectDualHistory: Type.Optional(Type.Boolean()),
          historyLimit: Type.Optional(Type.Number()),
        }),
      ),
      routers: Type.Optional(
        Type.Record(
          Type.String(),
          Type.Object({
            enabled: Type.Optional(Type.Boolean()),
            type: Type.Optional(Type.Union([Type.Literal("builtin"), Type.Literal("custom"), Type.Literal("configurable")])),
            module: Type.Optional(Type.String()),
            weight: Type.Optional(Type.Number()),
            options: Type.Optional(Type.Record(Type.String(), Type.Unknown())),
          }),
        ),
      ),
      pipeline: Type.Optional(
        Type.Object({
          onUserMessage: Type.Optional(Type.Array(Type.String())),
          onToolCallProposed: Type.Optional(Type.Array(Type.String())),
          onToolCallExecuted: Type.Optional(Type.Array(Type.String())),
        }),
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
          pin: Type.Optional(Type.Boolean()),
        }),
      ),
      webhooks: Type.Optional(
        Type.Array(
          Type.Object({
            url: Type.String(),
            format: Type.Optional(
              Type.Union([
                Type.Literal("json"),
                Type.Literal("discord"),
                Type.Literal("slack"),
              ]),
            ),
            events: Type.Optional(Type.Array(Type.String())),
            secret: Type.Optional(Type.String()),
          }),
        ),
      ),
      responseScanning: Type.Optional(
        Type.Object({
          enabled: Type.Optional(Type.Boolean()),
          action: Type.Optional(
            Type.Union([
              Type.Literal("warn"),
              Type.Literal("redact"),
              Type.Literal("block"),
            ]),
          ),
          scanSecrets: Type.Optional(Type.Boolean()),
          scanPii: Type.Optional(Type.Boolean()),
        }),
      ),
      budget: Type.Optional(
        Type.Object({
          enabled: Type.Optional(Type.Boolean()),
          dailyCap: Type.Optional(Type.Number()),
          monthlyCap: Type.Optional(Type.Number()),
          action: Type.Optional(
            Type.Union([
              Type.Literal("warn"),
              Type.Literal("pause_cloud"),
              Type.Literal("block"),
            ]),
          ),
          warnAt: Type.Optional(Type.Number()),
        }),
      ),
      behavioralAttestation: Type.Optional(
        Type.Object({
          enabled: Type.Optional(Type.Boolean()),
          logOnly: Type.Optional(Type.Boolean()),
          windowSize: Type.Optional(Type.Number()),
          blockThreshold: Type.Optional(Type.Number()),
        }),
      ),
      modelAdvisor: Type.Optional(
        Type.Object({
          enabled: Type.Optional(Type.Boolean()),
          checkIntervalWeeks: Type.Optional(Type.Number()),
          minSavingsPercent: Type.Optional(Type.Number()),
          minDiskSpaceGb: Type.Optional(Type.Number()),
          openrouterApiKey: Type.Optional(Type.String()),
          openrouter: Type.Optional(Type.Object({ enabled: Type.Optional(Type.Boolean()) })),
          llmfit: Type.Optional(Type.Object({ enabled: Type.Optional(Type.Boolean()) })),
          deberta: Type.Optional(Type.Object({
            enabled: Type.Optional(Type.Boolean()),
            autoUpdate: Type.Optional(Type.Boolean()),
          })),
          benchmark: Type.Optional(
            Type.Object({
              enabled: Type.Optional(Type.Boolean()),
              runs: Type.Optional(Type.Number()),
            }),
          ),
        }),
      ),
      taintTracking: Type.Optional(
        Type.Object({
          enabled: Type.Optional(Type.Boolean()),
          minValueLength: Type.Optional(Type.Number()),
          trackS2: Type.Optional(Type.Boolean()),
        }),
      ),
      debugLogging: Type.Optional(Type.Boolean()),
    }),
  ),
});

/**
 * Default configuration values.
 *
 * onUserMessage: rules first (fast, deterministic) then LLM judge for semantic detection.
 *   Both are needed: rules alone miss semantic sensitivity; LLM alone may miss
 *   keyword-level matches and override rule-based S2 detections with S1.
 * onToolCallProposed: rules-only by default (fast, no LLM overhead per tool call).
 *   Users can add "localModelDetector" to enable LLM detection for tool calls.
 * onToolCallExecuted: rules-only; sync LLM supplement is separately controlled
 *   by localModel.enabled (not by this checkpoint config).
 */
export const defaultPrivacyConfig = {
  enabled: true,
  s2Policy: "proxy" as "proxy" | "local",
  proxyPort: 8403,
  checkpoints: {
    onUserMessage: ["ruleDetector" as const, "localModelDetector" as const],
    onToolCallProposed: ["ruleDetector" as const],
    onToolCallExecuted: ["ruleDetector" as const],
  },
  rules: {
    keywords: {
      S2: [] as string[],
      S3: [] as string[],
    },
    patterns: {
      S2: [] as string[],
      S3: [] as string[],
    },
    tools: {
      S2: { tools: [] as string[], paths: [] as string[] },
      S3: { tools: [] as string[], paths: [] as string[] },
    },
  },
  localModel: {
    enabled: true,
    type: "openai-compatible" as const,
    model: "openbmb/minicpm4.1",
    endpoint: "http://localhost:11434",
  },
  guardAgent: {
    id: "guard",
    workspace: "~/.openclaw/workspace-guard",
    model: "ollama/openbmb/minicpm4.1",
  },
  localProviders: [] as string[],
  toolAllowlist: [] as string[],
  modelPricing: {
    "claude-sonnet-4.6": { inputPer1M: 3, outputPer1M: 15 },
    "claude-3.5-sonnet": { inputPer1M: 3, outputPer1M: 15 },
    "claude-3.5-haiku": { inputPer1M: 0.8, outputPer1M: 4 },
    "gpt-4o": { inputPer1M: 2.5, outputPer1M: 10 },
    "gpt-4o-mini": { inputPer1M: 0.15, outputPer1M: 0.6 },
    "o4-mini": { inputPer1M: 1.1, outputPer1M: 4.4 },
    "gemini-2.0-flash": { inputPer1M: 0.1, outputPer1M: 0.4 },
    "deepseek-chat": { inputPer1M: 0.27, outputPer1M: 1.1 },
  } as Record<string, { inputPer1M?: number; outputPer1M?: number }>,
  debugLogging: false,
  redaction: {
    internalIp: false,
    email: false,
    envVar: false,
    creditCard: false,
    chinesePhone: false,
    chineseId: false,
    chineseAddress: false,
    pin: false,
  },
  session: {
    isolateGuardHistory: true,
    baseDir: "~/.openclaw",
    injectDualHistory: true,
    historyLimit: 20,
  },
  routers: {
    privacy: { enabled: true, type: "builtin" as const },
  } as Record<string, { enabled?: boolean; type?: "builtin" | "custom" | "configurable"; module?: string; weight?: number; options?: Record<string, unknown> }>,
  pipeline: {
    onUserMessage: ["privacy"],
    onToolCallProposed: ["privacy"],
    onToolCallExecuted: ["privacy"],
  },
  responseScanning: {
    enabled: true,
    action: "warn" as "warn" | "redact" | "block",
    scanSecrets: true,
    scanPii: false,
  },
  behavioralAttestation: {
    enabled: false,   // flip to true to start collecting data
    logOnly: true,    // true = log+score only, never blocks; false = active gating
    windowSize: 10,
    blockThreshold: 0.8,
  },
  modelAdvisor: {
    enabled: false,
    checkIntervalWeeks: 2,
    minSavingsPercent: 20,
    minDiskSpaceGb: 10,
    openrouter: { enabled: true },
    llmfit: { enabled: true },
    deberta: { enabled: true, autoUpdate: true },
    benchmark: { enabled: true, runs: 3 },
  },
  taintTracking: {
    enabled: true,
    minValueLength: 8,
    trackS2: false,
  },
};

export const defaultInjectionConfig = {
  enabled: true,
  heuristics_only: false,
  block_threshold: 70,
  sanitise_threshold: 30,
  alert_channel: "1483608914774986943",
  exempt_sources: [] as string[],
  exempt_senders: ["1317396442993922061"],
  banned_senders: [] as string[],
};
