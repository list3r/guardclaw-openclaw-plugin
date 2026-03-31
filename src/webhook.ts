/**
 * GuardClaw Webhooks
 *
 * Fire-and-forget HTTP POST notifications for security events.
 * Supports Discord (rich embeds), Slack (blocks), and generic JSON formats.
 *
 * Key design decisions:
 *   - Never blocks the main request path — all dispatches are async/background
 *   - Optional HMAC-SHA256 signature for webhook authenticity (X-GuardClaw-Signature)
 *   - 5-second timeout per dispatch; failures logged to console.warn
 *   - events[] filter: omit to receive all events, or list specific ones
 */

import { createHmac } from "node:crypto";

// ── Types ──

export type WebhookFormat = "json" | "discord" | "slack";

export type WebhookEvent =
  | "s3_detected"
  | "s2_detected"
  | "injection_blocked"
  | "ban_triggered"
  | "budget_warning"
  | "budget_exceeded"
  | "response_scan_hit"
  | "secret_denied"
  | "secret_allowed";

export type WebhookConfig = {
  /** Webhook endpoint URL */
  url: string;
  /** Payload format. Default: "json" */
  format?: WebhookFormat;
  /**
   * Events to receive. Omit to receive all events, or list specific ones.
   * Example: ["s3_detected", "ban_triggered"]
   */
  events?: WebhookEvent[];
  /** Optional HMAC-SHA256 secret. Signature sent as X-GuardClaw-Signature: sha256=<hex> */
  secret?: string;
};

export type WebhookPayload = {
  event: WebhookEvent;
  timestamp: string;
  sessionKey?: string;
  level?: string;
  reason?: string;
  details?: Record<string, unknown>;
};

// ── Formatting ──

const EVENT_COLORS: Record<WebhookEvent, number> = {
  s3_detected:      0xff4444,
  s2_detected:      0xff8800,
  injection_blocked: 0x9900ff,
  ban_triggered:    0xff0000,
  budget_warning:   0xffaa00,
  budget_exceeded:  0xff2200,
  response_scan_hit: 0xff6600,
  secret_denied:    0xcc3300,
  secret_allowed:   0x00aa44,
};

const EVENT_LABELS: Record<WebhookEvent, string> = {
  s3_detected:       "🔴 S3 Private Data Detected",
  s2_detected:       "🟡 S2 Sensitive Data Detected",
  injection_blocked: "🟣 Prompt Injection Blocked",
  ban_triggered:     "🚫 Sender Banned",
  budget_warning:    "⚠️ Budget Warning",
  budget_exceeded:   "🛑 Budget Cap Exceeded",
  response_scan_hit: "🔎 Sensitive Content in Response",
  secret_denied:     "🔐 Secret Access Denied",
  secret_allowed:    "🔑 Secret Access Allowed",
};

function buildDiscordBody(payload: WebhookPayload): Record<string, unknown> {
  const fields: Array<{ name: string; value: string; inline?: boolean }> = [];
  if (payload.sessionKey) {
    fields.push({ name: "Session", value: `\`${payload.sessionKey.slice(0, 24)}…\``, inline: true });
  }
  if (payload.level) {
    fields.push({ name: "Level", value: payload.level, inline: true });
  }
  if (payload.reason) {
    fields.push({ name: "Reason", value: payload.reason.slice(0, 200) });
  }
  if (payload.details) {
    for (const [k, v] of Object.entries(payload.details).slice(0, 3)) {
      fields.push({ name: k, value: String(v).slice(0, 100), inline: true });
    }
  }
  return {
    embeds: [{
      title: EVENT_LABELS[payload.event],
      color: EVENT_COLORS[payload.event],
      timestamp: payload.timestamp,
      fields,
      footer: { text: "GuardClaw" },
    }],
  };
}

function buildSlackBody(payload: WebhookPayload): Record<string, unknown> {
  const label = EVENT_LABELS[payload.event];
  const lines: string[] = [`*${label}*`];
  if (payload.level) lines.push(`Level: ${payload.level}`);
  if (payload.reason) lines.push(`Reason: ${payload.reason.slice(0, 200)}`);
  if (payload.sessionKey) lines.push(`Session: \`${payload.sessionKey.slice(0, 24)}…\``);
  if (payload.details) {
    for (const [k, v] of Object.entries(payload.details).slice(0, 3)) {
      lines.push(`${k}: ${String(v).slice(0, 100)}`);
    }
  }
  return { text: lines.join("\n") };
}

// ── Dispatch ──

const WEBHOOK_TIMEOUT_MS = 5_000;

export async function dispatchWebhook(
  cfg: WebhookConfig,
  payload: WebhookPayload,
): Promise<void> {
  if (cfg.events && cfg.events.length > 0 && !cfg.events.includes(payload.event)) return;

  const format = cfg.format ?? "json";
  let body: Record<string, unknown>;

  if (format === "discord") {
    body = buildDiscordBody(payload);
  } else if (format === "slack") {
    body = buildSlackBody(payload);
  } else {
    body = { ...payload, source: "guardclaw" };
  }

  const bodyStr = JSON.stringify(body);
  const headers: Record<string, string> = { "Content-Type": "application/json" };

  if (cfg.secret) {
    const sig = createHmac("sha256", cfg.secret).update(bodyStr).digest("hex");
    headers["X-GuardClaw-Signature"] = `sha256=${sig}`;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS);
  try {
    await fetch(cfg.url, {
      method: "POST",
      headers,
      body: bodyStr,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Dispatch webhooks for an event — fire-and-forget, never throws.
 * Reads webhook list directly from callers to avoid live-config coupling.
 */
export function fireWebhooks(
  event: WebhookEvent,
  payload: Omit<WebhookPayload, "event" | "timestamp">,
  webhooks: WebhookConfig[],
): void {
  if (!webhooks || webhooks.length === 0) return;
  const full: WebhookPayload = { ...payload, event, timestamp: new Date().toISOString() };
  for (const cfg of webhooks) {
    dispatchWebhook(cfg, full).catch((err) => {
      console.warn(`[GuardClaw] Webhook dispatch failed (${cfg.url.slice(0, 50)}…): ${String(err)}`);
    });
  }
}
