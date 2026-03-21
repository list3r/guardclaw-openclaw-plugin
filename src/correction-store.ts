/**
 * GuardClaw Correction Store
 *
 * Stores misclassification corrections with embeddings for retrieval-augmented
 * few-shot learning. On each detection call, the most similar past corrections
 * are retrieved and injected as examples into the prompt.
 *
 * Flow:
 *   1. User flags a misclassification via dashboard/API
 *   2. Correction is stored with an embedding of the original message
 *   3. On subsequent detections, incoming message is embedded
 *   4. Top-K similar corrections are injected as few-shot examples
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import type { SensitivityLevel } from "./types.js";

// ── Types ───────────────────────────────────────────────────────────────

export type Correction = {
  id: string;
  /** The original message or content that was misclassified */
  message: string;
  /** What the model predicted */
  predicted: SensitivityLevel;
  /** What the correct level should be */
  corrected: SensitivityLevel;
  /** Human-readable reason for the correction */
  reason?: string;
  /** Pre-computed embedding vector (from nomic-embed-text) */
  embedding?: number[];
  /** ISO timestamp */
  timestamp: string;
};

export type CorrectionStoreConfig = {
  /** Path to the corrections JSON file */
  filePath?: string;
  /** Embedding endpoint (LM Studio OpenAI-compatible) */
  embeddingEndpoint?: string;
  /** Embedding model name */
  embeddingModel?: string;
  /** Max corrections to keep (oldest trimmed first) */
  maxCorrections?: number;
  /** Number of similar corrections to inject as few-shot examples */
  topK?: number;
};

// ── Constants ───────────────────────────────────────────────────────────

const DEFAULT_FILE_PATH = join(
  process.env.HOME ?? "/tmp",
  ".openclaw",
  "guardclaw-corrections.json",
);
const DEFAULT_EMBEDDING_ENDPOINT = "http://localhost:1234";
const DEFAULT_EMBEDDING_MODEL = "text-embedding-nomic-embed-text-v1.5";
const DEFAULT_MAX_CORRECTIONS = 200;
const DEFAULT_TOP_K = 3;
const EMBEDDING_TIMEOUT_MS = 10_000;

// ── Store ───────────────────────────────────────────────────────────────

let corrections: Correction[] = [];
let storeConfig: CorrectionStoreConfig = {};
let loaded = false;

function resolveFilePath(): string {
  return storeConfig.filePath ?? DEFAULT_FILE_PATH;
}

/** Load corrections from disk. Safe to call multiple times (no-ops after first). */
export function loadCorrections(config?: CorrectionStoreConfig): Correction[] {
  if (config) storeConfig = config;
  const filePath = resolveFilePath();
  try {
    if (existsSync(filePath)) {
      const raw = JSON.parse(readFileSync(filePath, "utf-8")) as {
        corrections?: Correction[];
      };
      corrections = Array.isArray(raw.corrections) ? raw.corrections : [];
    }
  } catch {
    console.warn("[GuardClaw] Failed to load corrections, starting fresh");
    corrections = [];
  }
  loaded = true;
  return corrections;
}

/** Persist corrections to disk. */
function saveCorrections(): void {
  const filePath = resolveFilePath();
  try {
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(
      filePath,
      JSON.stringify({ corrections, updatedAt: new Date().toISOString() }, null, 2),
      "utf-8",
    );
  } catch (err) {
    console.error("[GuardClaw] Failed to save corrections:", err);
  }
}

/** Get all corrections (read-only). */
export function getCorrections(): ReadonlyArray<Correction> {
  if (!loaded) loadCorrections();
  return corrections;
}

/**
 * Add a correction. Computes embedding if endpoint is available.
 * Returns the correction with its generated ID.
 */
export async function addCorrection(
  input: Omit<Correction, "id" | "timestamp" | "embedding">,
): Promise<Correction> {
  if (!loaded) loadCorrections();

  const correction: Correction = {
    ...input,
    id: generateId(),
    timestamp: new Date().toISOString(),
  };

  // Try to compute embedding for similarity search
  try {
    correction.embedding = await embedText(input.message);
  } catch (err) {
    console.warn("[GuardClaw] Could not compute correction embedding:", err);
  }

  corrections.push(correction);

  // Trim to max size (remove oldest first)
  const max = storeConfig.maxCorrections ?? DEFAULT_MAX_CORRECTIONS;
  if (corrections.length > max) {
    corrections = corrections.slice(-max);
  }

  saveCorrections();
  console.log(
    `[GuardClaw] Correction added: ${correction.predicted} → ${correction.corrected} (${correction.id})`,
  );
  return correction;
}

/** Delete a correction by ID. */
export function deleteCorrection(id: string): boolean {
  if (!loaded) loadCorrections();
  const before = corrections.length;
  corrections = corrections.filter((c) => c.id !== id);
  if (corrections.length < before) {
    saveCorrections();
    return true;
  }
  return false;
}

// ── Similarity Search ───────────────────────────────────────────────────

/**
 * Find the top-K most similar corrections to the given message.
 * Uses cosine similarity between embeddings.
 *
 * Returns corrections sorted by similarity (highest first).
 * Only returns corrections that have embeddings.
 */
export async function findSimilarCorrections(
  message: string,
  topK?: number,
): Promise<Array<Correction & { similarity: number }>> {
  if (!loaded) loadCorrections();
  const k = topK ?? storeConfig.topK ?? DEFAULT_TOP_K;

  // No corrections with embeddings → return empty
  const withEmbeddings = corrections.filter((c) => c.embedding && c.embedding.length > 0);
  if (withEmbeddings.length === 0) return [];

  let queryEmbedding: number[];
  try {
    queryEmbedding = await embedText(message);
  } catch {
    // If embedding fails, we can't do similarity search
    return [];
  }

  // Score each correction by cosine similarity
  const scored = withEmbeddings
    .map((c) => ({
      ...c,
      similarity: cosineSimilarity(queryEmbedding, c.embedding!),
    }))
    .filter((c) => c.similarity > 0.3) // minimum relevance threshold
    .sort((a, b) => b.similarity - a.similarity)
    .slice(0, k);

  return scored;
}

/**
 * Build few-shot example text from similar corrections.
 * Returns a string to inject before the [CONTENT] block, or empty string.
 */
export async function buildFewShotExamples(message: string): Promise<string> {
  const similar = await findSimilarCorrections(message);
  if (similar.length === 0) return "";

  const examples = similar.map(
    (c) =>
      `[EXAMPLE]\nMessage: ${c.message.slice(0, 300)}\nCorrect: {"level":"${c.corrected}","reason":"${c.reason ?? "corrected from " + c.predicted}"}\n[/EXAMPLE]`,
  );

  return (
    "The following are corrected examples for similar messages:\n" +
    examples.join("\n") +
    "\n\nNow classify the following:\n"
  );
}

// ── Authoritative Override ─────────────────────────────────────────────────────────

const AUTHORITATIVE_THRESHOLD = 0.7;

export type CorrectionOverride = {
  level: SensitivityLevel;
  reason: string;
  correctionId: string;
  similarity: number;
};

/**
 * Check if a high-confidence correction should authoritatively override
 * the model's classification. Returns the override level if a correction
 * with similarity > 0.7 exists, otherwise null.
 *
 * This makes corrections authoritative — when the model disagrees with
 * a very close correction, the correction wins.
 */
export async function getAuthoritativeOverride(
  message: string,
): Promise<CorrectionOverride | null> {
  const similar = await findSimilarCorrections(message, 1);
  if (similar.length === 0) return null;

  const best = similar[0];
  if (best.similarity < AUTHORITATIVE_THRESHOLD) return null;

  return {
    level: best.corrected,
    reason: `Correction override (${(best.similarity * 100).toFixed(0)}% match): ${best.reason ?? "corrected from " + best.predicted}`,
    correctionId: best.id,
    similarity: best.similarity,
  };
}

// ── Embedding ───────────────────────────────────────────────────────────

/**
 * Compute an embedding vector for the given text using the configured
 * embedding model (OpenAI-compatible /v1/embeddings endpoint).
 */
async function embedText(text: string): Promise<number[]> {
  const endpoint = storeConfig.embeddingEndpoint ?? DEFAULT_EMBEDDING_ENDPOINT;
  const model = storeConfig.embeddingModel ?? DEFAULT_EMBEDDING_MODEL;
  const url = `${endpoint}/v1/embeddings`;

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      input: text.slice(0, 2000), // nomic-embed-text handles up to 8K tokens but truncate for speed
    }),
    signal: AbortSignal.timeout(EMBEDDING_TIMEOUT_MS),
  });

  if (!response.ok) {
    throw new Error(`Embedding API error: ${response.status} ${response.statusText}`);
  }

  const data = (await response.json()) as {
    data?: Array<{ embedding?: number[] }>;
  };

  const embedding = data.data?.[0]?.embedding;
  if (!embedding || embedding.length === 0) {
    throw new Error("Embedding response missing vector data");
  }

  return embedding;
}

// ── Utilities ───────────────────────────────────────────────────────────

function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length || a.length === 0) return 0;
  let dotProduct = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denominator = Math.sqrt(normA) * Math.sqrt(normB);
  return denominator === 0 ? 0 : dotProduct / denominator;
}

function generateId(): string {
  return `corr_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}
