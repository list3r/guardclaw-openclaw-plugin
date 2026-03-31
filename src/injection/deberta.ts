/**
 * DeBERTa prompt injection classifier client.
 * Calls FastAPI server at http://127.0.0.1:8404/classify
 */

const BASE_URL = (() => {
  const url = process.env.GUARDCLAW_DEBERTA_URL ?? 'http://127.0.0.1:8404/classify';
  // If user set a full /classify URL, derive base from it; otherwise use as-is for base
  return url.endsWith('/classify') ? url.slice(0, -'/classify'.length) : url;
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
 * Tell the classifier service to hot-swap to a new model.
 * Fire-and-forget safe — returns ok:false if the service is unreachable.
 * The service downloads the model from HuggingFace and swaps in-place;
 * in-flight /classify requests complete against the old model.
 */
export async function triggerDebertaReload(modelId: string): Promise<{ ok: boolean; message: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), RELOAD_TIMEOUT_MS);
  try {
    const res = await fetch(RELOAD_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
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
