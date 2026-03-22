/**
 * GuardClaw Detector Core
 *
 * Main sensitivity detection engine that coordinates rule-based and model-based detection.
 */

import type {
  Checkpoint,
  DetectionContext,
  DetectionResult,
  DetectorType,
  PrivacyConfig,
  SensitivityLevel
} from "./types.js";
import { maxLevel } from "./types.js";
import { detectByRules } from "./rules.js";
import { detectByLocalModel } from "./local-model.js";
import { defaultPrivacyConfig } from "./config-schema.js";

/**
 * Main detection function that coordinates all detectors.
 *
 * Accepts either a raw `pluginConfig` (legacy — will merge with defaults)
 * or a pre-merged `PrivacyConfig` via the `resolvedConfig` option to avoid
 * double-merging when called from routers that already merged config.
 */
export async function detectSensitivityLevel(
  context: DetectionContext,
  pluginConfig: Record<string, unknown>,
  resolvedConfig?: PrivacyConfig,
): Promise<DetectionResult> {
  const privacyConfig = resolvedConfig ?? mergeWithDefaults(
    (pluginConfig?.privacy as PrivacyConfig) ?? {},
    defaultPrivacyConfig
  );

  // Check if privacy is enabled (skip when dry-run so dashboards get real classification)
  if (privacyConfig.enabled === false && !context.dryRun) {
    return {
      level: "S1",
      levelNumeric: 1,
      reason: "Privacy detection disabled",
      detectorType: "ruleDetector",
      confidence: 1.0,
    };
  }

  // Get detectors for this checkpoint
  const detectors = getDetectorsForCheckpoint(context.checkpoint, privacyConfig);

  if (detectors.length === 0) {
    // No detectors configured for this checkpoint, default to S1
    return {
      level: "S1",
      levelNumeric: 1,
      reason: "No detectors configured",
      detectorType: "ruleDetector",
      confidence: 1.0,
    };
  }

  // Run all configured detectors
  const results = await runDetectors(detectors, context, privacyConfig);

  // Merge results (take maximum level)
  return mergeDetectionResults(results);
}

/**
 * Get configured detectors for a specific checkpoint
 */
function getDetectorsForCheckpoint(
  checkpoint: Checkpoint,
  config: PrivacyConfig
): DetectorType[] {
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

/**
 * Run detectors and collect results.
 *
 * Short-circuits on high-confidence rule hits:
 * - S3 always skips remaining detectors (highest level, content stays local)
 * - S2 with confidence >= 1.0 (rule engine pattern/keyword match) also skips
 *   the LLM — the regex already knows, running inference adds only latency.
 *
 * S1 results and low-confidence hits proceed to the LLM classifier as normal.
 */
async function runDetectors(
  detectors: DetectorType[],
  context: DetectionContext,
  config: PrivacyConfig
): Promise<DetectionResult[]> {
  const results: DetectionResult[] = [];

  for (const detector of detectors) {
    try {
      let result: DetectionResult;

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

      // Short-circuit: skip LLM when rule engine already has a definitive answer.
      // S3 always short-circuits. S2 short-circuits only on high-confidence rule hits
      // (confidence === 1.0 means the regex/keyword matched — no ambiguity).
      const isHighConfidenceRuleHit =
        detector === "ruleDetector" && (result.confidence ?? 0) >= 1.0;
      if (result.level === "S3" || (result.level === "S2" && isHighConfidenceRuleHit)) {
        if (isHighConfidenceRuleHit && result.level === "S2") {
          console.debug(`[GuardClaw] Short-circuit: rule engine S2 hit (${result.reason}) — skipping LLM`);
        }
        break;
      }
    } catch (err) {
      console.error(`[GuardClaw] Detector ${detector} failed:`, err);
    }
  }

  return results;
}

/**
 * Merge multiple detection results into a single result
 * Takes the highest severity level and combines reasons
 */
function mergeDetectionResults(results: DetectionResult[]): DetectionResult {
  if (results.length === 0) {
    return {
      level: "S1",
      levelNumeric: 1,
      reason: "No detection results",
      detectorType: "ruleDetector",
      confidence: 0,
    };
  }

  if (results.length === 1) {
    return results[0];
  }

  // Find the highest level
  const levels = results.map((r) => r.level);
  const finalLevel = maxLevel(...levels);

  // Collect reasons from all detectors that contributed to the decision
  const relevantResults = results.filter((r) => r.level === finalLevel);
  const reasons = relevantResults
    .map((r) => r.reason)
    .filter((r): r is string => Boolean(r));

  // Calculate average confidence
  const confidences = results.map((r) => r.confidence ?? 0.5);
  const avgConfidence = confidences.reduce((a, b) => a + b, 0) / confidences.length;

  // Determine primary detector type (the one that found the highest level)
  const primaryDetector = relevantResults[0]?.detectorType ?? "ruleDetector";

  return {
    level: finalLevel,
    levelNumeric: results.find((r) => r.level === finalLevel)?.levelNumeric ?? 1,
    reason: reasons.length > 0 ? reasons.join("; ") : undefined,
    detectorType: primaryDetector,
    confidence: avgConfidence,
  };
}

/**
 * Merge user config with defaults
 */
function mergeWithDefaults(
  userConfig: PrivacyConfig,
  defaults: PrivacyConfig
): PrivacyConfig {
  return {
    enabled: userConfig.enabled ?? defaults.enabled,
    checkpoints: {
      onUserMessage: userConfig.checkpoints?.onUserMessage ?? defaults.checkpoints?.onUserMessage,
      onToolCallProposed:
        userConfig.checkpoints?.onToolCallProposed ?? defaults.checkpoints?.onToolCallProposed,
      onToolCallExecuted:
        userConfig.checkpoints?.onToolCallExecuted ?? defaults.checkpoints?.onToolCallExecuted,
    },
    rules: {
      keywords: {
        S2: userConfig.rules?.keywords?.S2 ?? defaults.rules?.keywords?.S2,
        S3: userConfig.rules?.keywords?.S3 ?? defaults.rules?.keywords?.S3,
      },
      patterns: {
        S2: userConfig.rules?.patterns?.S2 ?? defaults.rules?.patterns?.S2,
        S3: userConfig.rules?.patterns?.S3 ?? defaults.rules?.patterns?.S3,
      },
      tools: {
        S2: {
          tools: userConfig.rules?.tools?.S2?.tools ?? defaults.rules?.tools?.S2?.tools,
          paths: userConfig.rules?.tools?.S2?.paths ?? defaults.rules?.tools?.S2?.paths,
        },
        S3: {
          tools: userConfig.rules?.tools?.S3?.tools ?? defaults.rules?.tools?.S3?.tools,
          paths: userConfig.rules?.tools?.S3?.paths ?? defaults.rules?.tools?.S3?.paths,
        },
      },
    },
    localModel: {
      enabled: userConfig.localModel?.enabled ?? defaults.localModel?.enabled,
      type: userConfig.localModel?.type ?? defaults.localModel?.type,
      provider: userConfig.localModel?.provider ?? defaults.localModel?.provider,
      model: userConfig.localModel?.model ?? defaults.localModel?.model,
      endpoint: userConfig.localModel?.endpoint ?? defaults.localModel?.endpoint,
      apiKey: userConfig.localModel?.apiKey ?? defaults.localModel?.apiKey,
      module: userConfig.localModel?.module ?? defaults.localModel?.module,
    },
    guardAgent: {
      id: userConfig.guardAgent?.id ?? defaults.guardAgent?.id,
      workspace: userConfig.guardAgent?.workspace ?? defaults.guardAgent?.workspace,
      model: userConfig.guardAgent?.model ?? defaults.guardAgent?.model,
    },
    session: {
      isolateGuardHistory:
        userConfig.session?.isolateGuardHistory ?? defaults.session?.isolateGuardHistory,
      baseDir: userConfig.session?.baseDir ?? defaults.session?.baseDir,
      injectDualHistory:
        userConfig.session?.injectDualHistory ?? defaults.session?.injectDualHistory,
      historyLimit: userConfig.session?.historyLimit ?? defaults.session?.historyLimit,
    },
  };
}
