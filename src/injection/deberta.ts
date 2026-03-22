/**
 * DeBERTa prompt injection classifier client.
 * Calls FastAPI server at http://127.0.0.1:8404/classify
 */

const ENDPOINT = process.env.GUARDCLAW_DEBERTA_URL ?? 'http://127.0.0.1:8404/classify';
const TIMEOUT_MS = 5000;

export interface DebertaResult {
  label: 0 | 1;
  score: number;
  injection: boolean;
  error?: string;
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
