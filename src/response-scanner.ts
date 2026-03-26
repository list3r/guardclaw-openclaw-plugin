/**
 * GuardClaw Response Scanner
 *
 * Scans LLM responses for accidental data leakage — secrets and credentials
 * that a cloud model may have echoed from tool results or injected context.
 *
 * Runs synchronously in before_message_write so the response can be
 * modified (redacted or blocked) before entering the transcript.
 *
 * Design decisions:
 *   - HIGH-confidence patterns only to keep false-positive rates low
 *   - Secrets off by default for scanPii — email/phone FP rate too high
 *   - Redact replaces matched spans, block replaces the whole response
 *   - Returns a scan result so callers can log, webhook, and act independently
 */

export type ResponseScanAction = "warn" | "redact" | "block";

export type ResponseScanConfig = {
  /** Enable response scanning. Default: false */
  enabled?: boolean;
  /** Action on hit. Default: "warn" */
  action?: ResponseScanAction;
  /** Scan for API keys, tokens, private keys, connection strings. Default: true */
  scanSecrets?: boolean;
  /** Scan for PII (SSN, credit cards). Higher false-positive rate. Default: false */
  scanPii?: boolean;
};

export type ResponseScanResult = {
  hit: boolean;
  matches: string[];
  reason?: string;
  /** Populated when action === "redact" */
  redacted?: string;
  action: ResponseScanAction;
};

// ── High-confidence secret patterns ──
// These are designed for very low false-positive rates. Each pattern matches
// something that is almost certainly a secret and unlikely in normal prose.

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  // PEM private keys
  {
    name: "private_key",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/i,
  },
  // OpenAI — classic sk-... and newer sk-proj-... format
  {
    name: "openai_key",
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b/,
  },
  // Anthropic
  {
    name: "anthropic_key",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
  },
  // AWS access key ID
  {
    name: "aws_access_key",
    pattern: /\b(?:AKIA|ASIA|AROA|ANPA|ANVA|AIDA)[0-9A-Z]{16}\b/,
  },
  // GitHub tokens (fine-grained and classic)
  {
    name: "github_token",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/,
  },
  // Google service account / API key format (AIza...)
  {
    name: "google_key",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
  },
  // Bearer token in HTTP header context
  {
    name: "bearer_token",
    pattern: /Authorization:\s*Bearer\s+[A-Za-z0-9._\-]{20,}/i,
  },
  // Database connection strings with embedded credentials
  {
    name: "db_connection_string",
    pattern: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^:@\s]{1,64}:[^@\s]{6,}@/i,
  },
  // .env style key=value with a long value (high-entropy credentials)
  {
    name: "env_credential",
    pattern: /(?:API_KEY|SECRET(?:_KEY)?|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|APP_SECRET)\s*=\s*["']?[A-Za-z0-9+\/=_\-]{20,}["']?/i,
  },
];

// ── PII patterns (off by default — higher false-positive rate) ──

const PII_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  // US Social Security Number
  { name: "us_ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
  // 16-digit credit card with spaces/dashes
  { name: "credit_card", pattern: /\b(?:\d{4}[- ]){3}\d{4}\b/ },
];

// ── Implementation ──

function redactMatches(
  text: string,
  found: Array<{ name: string; match: string }>,
): string {
  let result = text;
  for (const { name, match } of found) {
    // Replace ALL occurrences of this match
    result = result.split(match).join(`[REDACTED:${name.toUpperCase()}]`);
  }
  return result;
}

export function scanResponse(
  text: string,
  config: ResponseScanConfig,
): ResponseScanResult {
  const action = config.action ?? "warn";
  const scanSecrets = config.scanSecrets !== false; // default true
  const scanPii = config.scanPii === true;           // default false

  const found: Array<{ name: string; match: string }> = [];

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

  let redacted: string | undefined;
  if (action === "redact") {
    redacted = redactMatches(text, found);
  }

  return { hit: true, matches: matchNames, reason, redacted, action };
}
