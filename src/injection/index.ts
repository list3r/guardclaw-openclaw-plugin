/**
 * GuardClaw S0 — Prompt Injection Detection
 *
 * The ML classification layer is inspired by LLM Guard
 * (https://github.com/protectai/llm-guard, MIT License) by Protect AI, which
 * pioneered using deberta-v3-base-prompt-injection-v2 for injection detection.
 * No code was copied — GuardClaw's two-layer pipeline (heuristics + DeBERTa)
 * and all regex patterns are original. The DeBERTa model itself is separately
 * licensed Apache 2.0 by Protect AI on HuggingFace.
 *
 * Pipeline position: runs BEFORE S1 (PII redaction).
 *
 * Input:  raw content string + source type
 * Output: { pass, score, action, sanitised?, matches, blocked_reason? }
 */

import { runHeuristics } from './heuristics.js';
import { runDebertaClassifier, type DebertaResult } from './deberta.js';
import { sanitiseContent } from './sanitiser.js';
import type { InjectionConfig } from '../types.js';

export type InjectionSource = 'web_fetch' | 'email' | 'discord' | 'file' | 'api_response' | 'user_message';

export interface InjectionResult {
  pass: boolean;           // true = content is clean
  score: number;           // 0-100 injection risk
  action: 'pass' | 'sanitise' | 'block';
  sanitised?: string;      // content with injections redacted (if action=sanitise)
  matches: string[];       // which patterns/signals triggered
  blocked_reason?: string; // human-readable reason (if action=block)
}

const DEFAULT_BLOCK_THRESHOLD = 70;
const DEFAULT_SANITISE_THRESHOLD = 30;

export const SECURITY_CHANNEL = '1483608914774986943';

export function formatBlockAlert(result: InjectionResult, source: string, preview: string): string {
  return `🛡️ **GuardClaw S0 — Injection Blocked**
> **Source:** ${source}
> **Score:** ${result.score}/100
> **Patterns:** ${result.matches.join(', ')}
> **Preview:** \`${preview.slice(0, 100)}${preview.length > 100 ? '...' : ''}\`
>
> Content blocked and not passed to model. Review in guardclaw-injections.log`;
}

let _injectionConfig: InjectionConfig = {};

/** Initialize the injection config (called from plugin register). */
export function initInjectionConfig(config: InjectionConfig): void {
  _injectionConfig = config;
}

/** Get the current injection config. */
export function getLiveInjectionConfig(): InjectionConfig {
  return _injectionConfig;
}

/** Update injection config (e.g. from hot-reload). */
export function updateInjectionConfig(config: InjectionConfig): void {
  _injectionConfig = config;
}

export async function detectInjection(
  content: string,
  source: InjectionSource,
  config?: InjectionConfig,
): Promise<InjectionResult> {
  const cfg = config ?? _injectionConfig;

  // Check exempt sources
  if (cfg.exempt_sources?.includes(source)) {
    return { pass: true, score: 0, action: 'pass', matches: [] };
  }

  const blockThreshold = cfg.block_threshold ?? DEFAULT_BLOCK_THRESHOLD;
  const sanitiseThreshold = cfg.sanitise_threshold ?? DEFAULT_SANITISE_THRESHOLD;

  // Layer 1: Heuristics (always runs, fast)
  const heuristic = runHeuristics(content);

  let finalScore = heuristic.score;
  let debertaResult: DebertaResult | null = null;

  // Layer 2: Deberta (only if heuristic score is ambiguous 20-80, and not heuristics_only)
  if (!cfg.heuristics_only && heuristic.score >= 20 && heuristic.score <= 80) {
    debertaResult = await runDebertaClassifier(content);

    if (!debertaResult.error) {
      if (debertaResult.injection) {
        // Deberta confirmed injection — boost score
        finalScore = Math.max(finalScore, 70 + (debertaResult.score * 30));
      } else if (debertaResult.score > 0.7 && debertaResult.label === 0) {
        // Deberta confident it's benign — reduce score
        finalScore = Math.min(finalScore, 25);
      }
    }
  }

  // Determine action
  let action: 'pass' | 'sanitise' | 'block';
  if (finalScore < sanitiseThreshold) {
    action = 'pass';
  } else if (finalScore < blockThreshold) {
    action = 'sanitise';
  } else {
    action = 'block';
  }

  // Sanitise if needed
  let sanitised: string | undefined;
  if (action === 'sanitise') {
    sanitised = sanitiseContent(content, heuristic.matchedPatterns);
  }

  return {
    pass: action === 'pass',
    score: Math.round(finalScore),
    action,
    sanitised,
    matches: heuristic.matches,
    blocked_reason: action === 'block'
      ? `Injection detected (score ${Math.round(finalScore)}): ${heuristic.matches.join(', ')}`
      : undefined,
  };
}
