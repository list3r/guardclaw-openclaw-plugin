/**
 * DeBERTa prompt injection classifier client.
 * Calls FastAPI server at http://127.0.0.1:8404/classify
 */

/**
 * GCF-017: Validate GUARDCLAW_DEBERTA_URL is loopback-only (http://127.0.0.1 or http://localhost).
 * Rejects any non-loopback URL to prevent SSRF — an attacker setting this env var
 * would otherwise redirect all injection checks to an attacker-controlled server,
 * bypassing S0 detection and exfiltrating message content.
 */
const BASE_URL = (() => {
  const envUrl = process.env.GUARDCLAW_DEBERTA_URL;
  const DEFAULT = 'http://127.0.0.1:8404';

  if (!envUrl) return DEFAULT;

  // Strip trailing /classify if present
  const base = envUrl.endsWith('/classify') ? envUrl.slice(0, -'/classify'.length) : envUrl;

  // Only allow loopback hosts
  try {
    const parsed = new URL(base);
    if (parsed.protocol !== 'http:') {
      console.warn(`[GuardClaw] GUARDCLAW_DEBERTA_URL rejected — only http: scheme allowed (got ${parsed.protocol}). Using default.`);
      return DEFAULT;
    }
    const host = parsed.hostname;
    if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
      console.warn(`[GuardClaw] GUARDCLAW_DEBERTA_URL rejected — non-loopback host '${host}' not allowed (SSRF prevention). Using default.`);
      return DEFAULT;
    }
    return base;
  } catch {
    console.warn(`[GuardClaw] GUARDCLAW_DEBERTA_URL is not a valid URL — using default.`);
    return DEFAULT;
  }
})();
const ENDPOINT = `${BASE_URL}/classify`;
const RELOAD_ENDPOINT = `${BASE_URL}/reload`;
const TIMEOUT_MS = 5000;
const RELOAD_TIMEOUT_MS = 300_000; // 5 min — model download can be slow

export interface DebertaResult {
  label: 0 | 1;
  score: number;
  injection: boolean;
  error?: string;
}

/**
 * Allowlist of permitted DeBERTa model IDs (GCF-018).
 * Only models in this list can be loaded via triggerDebertaReload().
 * Prevents an attacker from hot-swapping in a malicious classifier.
 * Add new trusted model versions here as they are released.
 */
const ALLOWED_DEBERTA_MODELS = new Set([
  'protectai/deberta-v3-base-prompt-injection-v2',
  'protectai/deberta-v3-base-prompt-injection',
  'laiyer/deberta-v3-base-prompt-injection',
]);

/**
 * Get the reload API token from environment (GCF-018).
 * Set GUARDCLAW_DEBERTA_RELOAD_TOKEN to a random secret before starting the service.
 * The service reads the same env var and requires it on /reload requests.
 */
const RELOAD_API_TOKEN = process.env.GUARDCLAW_DEBERTA_RELOAD_TOKEN ?? '';

/**
 * Tell the classifier service to hot-swap to a new model.
 * Fire-and-forget safe — returns ok:false if the service is unreachable.
 * The service downloads the model from HuggingFace and swaps in-place;
 * in-flight /classify requests complete against the old model.
 *
 * GCF-018: Model ID is checked against ALLOWED_DEBERTA_MODELS before sending.
 * Reload requests include the GUARDCLAW_DEBERTA_RELOAD_TOKEN for authentication.
 */
export async function triggerDebertaReload(modelId: string): Promise<{ ok: boolean; message: string }> {
  // Model ID allowlist check (GCF-018)
  if (!ALLOWED_DEBERTA_MODELS.has(modelId)) {
    console.warn(`[GuardClaw] DeBERTa reload rejected — model '${modelId}' is not in the allowlist.`);
    return { ok: false, message: `Model '${modelId}' not in allowed list` };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), RELOAD_TIMEOUT_MS);
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (RELOAD_API_TOKEN) {
      headers['X-GuardClaw-Token'] = RELOAD_API_TOKEN;
    }
    const res = await fetch(RELOAD_ENDPOINT, {
      method: 'POST',
      headers,
      body: JSON.stringify({ model: modelId }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return { ok: false, message: `HTTP ${res.status}` };
    const data = await res.json() as { ok?: boolean; model?: string; note?: string };
    return { ok: true, message: data.note ?? `Loaded ${data.model ?? modelId}` };
  } catch (err: any) {
    clearTimeout(timer);
    return { ok: false, message: err.name === 'AbortError' ? 'Timeout' : (err.message ?? 'Service unreachable') };
  }
}

export async function runDebertaClassifier(content: string): Promise<DebertaResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (!res.ok) {
      return { label: 0, score: 0, injection: false, error: `HTTP ${res.status}` };
    }

    const data = await res.json() as DebertaResult;
    return data;
  } catch (err: any) {
    clearTimeout(timer);
    if (err.name === 'AbortError') {
      return { label: 0, score: 0, injection: false, error: 'Timeout' };
    }
    return { label: 0, score: 0, injection: false, error: err.message ?? 'Unknown error' };
  }
}
