/**
 * GuardClaw Secret Manager
 *
 * Provides tracked access to macOS Keychain secrets for Guard Agent (S3) sessions.
 *
 * Security model:
 *   - Secrets are only accessible inside S3 guard sessions (never S1/S2/cloud)
 *   - Every retrieved secret value is tracked in a per-session in-memory set
 *   - Tracked secrets are redacted from any content that might leave the guard
 *     session boundary (assistant responses, tool results, memory writes)
 *   - Network tools are blocked in guard sessions to prevent outbound exfiltration
 *   - Secret values are cleared from memory when the guard session ends
 *
 * Usage by the guard agent:
 *   bash -c "security find-generic-password -s 'ServiceName' -a 'AccountName' -w"
 *
 *   GuardClaw intercepts this bash command in before_tool_call, marks the session
 *   as having a pending keychain fetch, then tracks the result in tool_result_persist
 *   before it enters the model context.  The secret is then redacted from all
 *   outbound content (assistant replies, memory files, clean history).
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

// ── Constants ─────────────────────────────────────────────────────────────────

/** Maximum size of a secret value read from Keychain. */
const MAX_SECRET_BYTES = 8192;

/** Maximum number of secrets tracked per guard session (DoS guard). */
const MAX_TRACKED_PER_SESSION = 50;

/**
 * Minimum length for a value to be tracked as a secret.
 * Values shorter than this are likely false positives (e.g. "ok", "0").
 */
const MIN_SECRET_LENGTH = 4;

// ── Per-session state ─────────────────────────────────────────────────────────

/** sessionKey → Set of secret values retrieved during that guard session. */
const trackedSecrets = new Map<string, Set<string>>();

/**
 * Sessions whose next bash tool result should be treated as a Keychain secret.
 * Set in before_tool_call when a `security find-generic-password -w` command is
 * detected; consumed (and cleared) in tool_result_persist.
 */
const pendingKeychainFetch = new Set<string>();

// ── Keychain access ───────────────────────────────────────────────────────────

/**
 * Read a secret from macOS Keychain using the security(1) CLI.
 * Uses execFile (no shell invocation) to prevent command injection.
 *
 * @param service  The Keychain service name
 * @param account  The Keychain account name
 */
export async function readKeychainSecret(
  service: string,
  account: string,
): Promise<{ value: string } | { error: string }> {
  if (!isValidLabel(service) || !isValidLabel(account)) {
    return { error: "Invalid service or account — only printable ASCII (1–255 chars) allowed" };
  }

  try {
    const { stdout } = await execFileAsync(
      "security",
      ["find-generic-password", "-s", service, "-a", account, "-w"],
      { timeout: 5000, maxBuffer: MAX_SECRET_BYTES },
    );
    return { value: stdout.trim() };
  } catch (err: unknown) {
    const e = err as { stderr?: string; message?: string };
    return { error: e.stderr?.trim() || e.message || String(err) };
  }
}

/**
 * Validate that a service/account label is safe to pass to security(1).
 * Restricted to printable ASCII — execFile does not invoke a shell, but this
 * is a defense-in-depth measure in case the value is used elsewhere.
 */
function isValidLabel(s: string): boolean {
  return (
    typeof s === "string" &&
    s.length > 0 &&
    s.length <= 255 &&
    /^[\x20-\x7E]+$/.test(s)
  );
}

// ── Secret tracking ───────────────────────────────────────────────────────────

/**
 * Add a secret value to the per-session tracker.
 * Silently ignores values that are too short, empty, or would exceed the cap.
 */
export function trackSecret(sessionKey: string, value: string): void {
  if (!value || value.length < MIN_SECRET_LENGTH) return;
  let set = trackedSecrets.get(sessionKey);
  if (!set) {
    set = new Set();
    trackedSecrets.set(sessionKey, set);
  }
  if (set.size < MAX_TRACKED_PER_SESSION) {
    set.add(value);
  }
}

/**
 * Mark that the next bash tool result for this guard session should be treated
 * as a Keychain secret and tracked automatically.
 * Called from before_tool_call when a `security find-generic-password -w`
 * command is detected in the bash parameters.
 */
export function markKeychainFetchPending(sessionKey: string): void {
  pendingKeychainFetch.add(sessionKey);
}

/**
 * Check and clear the pending keychain fetch flag for a session.
 * Returns true if a fetch was pending — the caller should track the bash result.
 */
export function consumeKeychainFetchPending(sessionKey: string): boolean {
  const had = pendingKeychainFetch.has(sessionKey);
  pendingKeychainFetch.delete(sessionKey);
  return had;
}

/**
 * Returns true if `text` contains any tracked secret value for this session.
 */
export function containsTrackedSecret(sessionKey: string, text: string): boolean {
  const set = trackedSecrets.get(sessionKey);
  if (!set) return false;
  for (const secret of set) {
    if (text.includes(secret)) return true;
  }
  return false;
}

/**
 * Replace all tracked secret values in `text` with the `[REDACTED:SECRET]` tag.
 * Uses string split/join instead of RegExp to avoid escaping issues with special
 * characters that are common in passwords.
 */
export function redactTrackedSecrets(sessionKey: string, text: string): string {
  const set = trackedSecrets.get(sessionKey);
  if (!set || set.size === 0) return text;
  let result = text;
  for (const secret of set) {
    result = result.split(secret).join("[REDACTED:SECRET]");
  }
  return result;
}

/**
 * Clear all tracked secrets for a guard session and remove the pending-fetch flag.
 * Must be called when the guard session ends to prevent indefinite memory retention.
 */
export function clearSessionSecrets(sessionKey: string): void {
  trackedSecrets.delete(sessionKey);
  pendingKeychainFetch.delete(sessionKey);
}

// ── Network tool detection ────────────────────────────────────────────────────

/**
 * Exact tool names known to make outbound network requests.
 * Guard sessions are blocked from calling any of these to prevent secret
 * exfiltration via HTTP/WebSocket/etc.
 */
const NETWORK_TOOL_EXACT = new Set([
  "web_fetch", "web_search", "http_get", "http_post", "http_request",
  "fetch", "curl", "wget", "browse", "browser", "websearch", "search_web",
  "url_fetch", "http", "get_url", "post_url",
]);

/**
 * Returns true if the tool name matches a known network tool.
 * Checks both an exact-name set and heuristic substrings for MCP-namespaced tools
 * (e.g. `mcp__brave_search__search`, `mcp__fetch__fetch`).
 */
export function isNetworkTool(toolName: string): boolean {
  const lower = toolName.toLowerCase();
  if (NETWORK_TOOL_EXACT.has(lower)) return true;
  if (lower.startsWith("mcp__") && (
    lower.includes("fetch") ||
    lower.includes("http") ||
    lower.includes("search") ||
    lower.includes("browse") ||
    lower.includes("curl")
  )) return true;
  return false;
}

// ── Keychain command detection ────────────────────────────────────────────────

/**
 * Detect a `security find-generic-password -w` command inside a bash string.
 * Supports both `-s <service> -a <account>` and `-a <account> -s <service>` orderings,
 * with and without quotes around the values.
 *
 * Returns the parsed service and account if found; null if the command does not
 * look like a Keychain password fetch.
 */
export function parseKeychainCommand(command: string): { service: string; account: string } | null {
  if (!command.includes("security") || !command.includes("find-generic-password")) return null;

  // -s before -a
  const m1 = command.match(
    /\bsecurity\s+find-generic-password\b[^|]*?-s\s+["']([^"']+)["'][^|]*?-a\s+["']([^"']+)["'][^|]*?-w\b/,
  ) || command.match(
    /\bsecurity\s+find-generic-password\b[^|]*?-s\s+(\S+)[^|]*?-a\s+(\S+)[^|]*?-w\b/,
  );
  if (m1) return { service: m1[1], account: m1[2] };

  // -a before -s
  const m2 = command.match(
    /\bsecurity\s+find-generic-password\b[^|]*?-a\s+["']([^"']+)["'][^|]*?-s\s+["']([^"']+)["'][^|]*?-w\b/,
  ) || command.match(
    /\bsecurity\s+find-generic-password\b[^|]*?-a\s+(\S+)[^|]*?-s\s+(\S+)[^|]*?-w\b/,
  );
  if (m2) return { service: m2[2], account: m2[1] };

  return null;
}
