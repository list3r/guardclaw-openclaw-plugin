// src/webhook.ts
import { createHmac } from "crypto";
var EVENT_COLORS = {
  s3_detected: 16729156,
  s2_detected: 16746496,
  injection_blocked: 10027263,
  ban_triggered: 16711680,
  budget_warning: 16755200,
  budget_exceeded: 16720384,
  response_scan_hit: 16737792,
  secret_denied: 13382400,
  secret_allowed: 43588
};
var EVENT_LABELS = {
  s3_detected: "\u{1F534} S3 Private Data Detected",
  s2_detected: "\u{1F7E1} S2 Sensitive Data Detected",
  injection_blocked: "\u{1F7E3} Prompt Injection Blocked",
  ban_triggered: "\u{1F6AB} Sender Banned",
  budget_warning: "\u26A0\uFE0F Budget Warning",
  budget_exceeded: "\u{1F6D1} Budget Cap Exceeded",
  response_scan_hit: "\u{1F50E} Sensitive Content in Response",
  secret_denied: "\u{1F510} Secret Access Denied",
  secret_allowed: "\u{1F511} Secret Access Allowed"
};
function buildDiscordBody(payload) {
  const fields = [];
  if (payload.sessionKey) {
    fields.push({ name: "Session", value: `\`${payload.sessionKey.slice(0, 24)}\u2026\``, inline: true });
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
      footer: { text: "GuardClaw" }
    }]
  };
}
function buildSlackBody(payload) {
  const label = EVENT_LABELS[payload.event];
  const lines = [`*${label}*`];
  if (payload.level) lines.push(`Level: ${payload.level}`);
  if (payload.reason) lines.push(`Reason: ${payload.reason.slice(0, 200)}`);
  if (payload.sessionKey) lines.push(`Session: \`${payload.sessionKey.slice(0, 24)}\u2026\``);
  if (payload.details) {
    for (const [k, v] of Object.entries(payload.details).slice(0, 3)) {
      lines.push(`${k}: ${String(v).slice(0, 100)}`);
    }
  }
  return { text: lines.join("\n") };
}
var WEBHOOK_TIMEOUT_MS = 5e3;
async function dispatchWebhook(cfg, payload) {
  if (cfg.events && cfg.events.length > 0 && !cfg.events.includes(payload.event)) return;
  const format = cfg.format ?? "json";
  let body;
  if (format === "discord") {
    body = buildDiscordBody(payload);
  } else if (format === "slack") {
    body = buildSlackBody(payload);
  } else {
    body = { ...payload, source: "guardclaw" };
  }
  const bodyStr = JSON.stringify(body);
  const headers = { "Content-Type": "application/json" };
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
      signal: controller.signal
    });
  } finally {
    clearTimeout(timer);
  }
}
function fireWebhooks(event, payload, webhooks) {
  if (!webhooks || webhooks.length === 0) return;
  const full = { ...payload, event, timestamp: (/* @__PURE__ */ new Date()).toISOString() };
  for (const cfg of webhooks) {
    dispatchWebhook(cfg, full).catch((err) => {
      console.warn(`[GuardClaw] Webhook dispatch failed (${cfg.url.slice(0, 50)}\u2026): ${String(err)}`);
    });
  }
}

export {
  dispatchWebhook,
  fireWebhooks
};
