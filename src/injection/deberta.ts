import { spawn } from 'node:child_process';
import * as path from 'node:path';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// From dist/ → ../scripts/injection_classifier.py
const CLASSIFIER_SCRIPT = path.join(__dirname, '../scripts/injection_classifier.py');

// Use venv python if available (set up via: python3 -m venv .venv && pip install torch transformers)
const VENV_PYTHON = path.join(__dirname, '../.venv/bin/python3');
const PYTHON_BIN = existsSync(VENV_PYTHON) ? VENV_PYTHON : 'python3';

const TIMEOUT_MS = 5000;

export interface DebertaResult {
  label: 0 | 1;
  score: number;
  injection: boolean;
  error?: string;
}

export async function runDebertaClassifier(content: string): Promise<DebertaResult> {
  return new Promise((resolve) => {
    let resolved = false;

    const proc = spawn(PYTHON_BIN, [CLASSIFIER_SCRIPT], {
      timeout: TIMEOUT_MS,
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => { stdout += data; });
    proc.stderr.on('data', (data) => { stderr += data; });

    proc.on('close', (code) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(timer);
      if (code !== 0) {
        resolve({ label: 0, score: 0, injection: false, error: stderr || 'Process failed' });
        return;
      }
      try {
        const result = JSON.parse(stdout) as DebertaResult;
        resolve(result);
      } catch {
        resolve({ label: 0, score: 0, injection: false, error: 'Invalid JSON response' });
      }
    });

    proc.on('error', (err) => {
      if (resolved) return;
      resolved = true;
      clearTimeout(timer);
      resolve({ label: 0, score: 0, injection: false, error: err.message });
    });

    // Send content to stdin
    proc.stdin.write(content);
    proc.stdin.end();

    // Fallback timeout
    const timer = setTimeout(() => {
      if (resolved) return;
      resolved = true;
      proc.kill();
      resolve({ label: 0, score: 0, injection: false, error: 'Timeout' });
    }, TIMEOUT_MS + 1000);
  });
}
