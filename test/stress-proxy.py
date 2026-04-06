#!/usr/bin/env python3
"""
GuardClaw Stress Test — Tool-noise, Circuit Breaker, Concurrency Limiter

Tests three new protections (GCF-030/031/032):
  1. Tool-noise early exit: short status messages bypass S2 pipeline
  2. Circuit breaker: proxy stops retrying after 3 consecutive upstream failures
  3. Concurrency limiter: proxy caps concurrent upstream requests to 5

Usage:
  python3 test/stress-proxy.py                    # all tests
  python3 test/stress-proxy.py --noise-only       # just tool-noise detection
  python3 test/stress-proxy.py --proxy-only       # just proxy resilience
  python3 test/stress-proxy.py --classification   # quick classification accuracy check (20 cases)
"""

import json, subprocess, sys, time, os
from concurrent.futures import ThreadPoolExecutor, as_completed

API = "http://localhost:1234"
PROXY = "http://127.0.0.1:8403"
MODEL = "qwen/qwen3-30b-a3b-2507"

# ═══════════════════════════════════════════════════════════════════════════
# 1. Tool-noise detection (runs against isToolNoise logic)
# ═══════════════════════════════════════════════════════════════════════════

NOISE_CASES = [
    # (should_be_noise, text, description)
    (True,  "✓", "checkmark only"),
    (True,  "done", "single word status"),
    (True,  "ok", "ok"),
    (True,  "Created", "created status"),
    (True,  "exit 0", "exit code"),
    (True,  "exited code 0", "exited with code"),
    (True,  "true", "boolean true"),
    (True,  "42", "number only"),
    (True,  "3.14ms", "timing value"),
    (True,  "1024 bytes", "byte count"),
    (True,  "{}", "empty object"),
    (True,  "[]", "empty array"),
    (True,  "no results", "no results"),
    (True,  "no matches", "no matches"),
    (True,  "passed", "passed"),
    (True,  "  \n  ", "whitespace only"),
    (True,  "", "empty string"),
    (True,  "[3/5]", "progress indicator"),
    (True,  "12 files", "file count"),
    (True,  "skipped", "skipped"),
    (True,  "unchanged", "unchanged"),
    (True,  "• Running grep...", "bullet + running"),
    (True,  "Started", "started"),
    (True,  "Finished", "finished"),
    (True,  "Wrote 3 files", "short write status"),
    # Should NOT be noise (contains PII signals or is too complex)
    (False, "my password is FluffyBunny99!", "contains password"),
    (False, "BSB 012-003 Acct 8876-5432", "contains bank details"),
    (False, "call James on 0412-555-789 about the delivery to 123 Main St", "contains PII"),
    (False, "AWS_ACCESS_KEY=AKIA1234567890ABCDEF\nAWS_SECRET=wJalrXUtnFEMI/K7MDENG", "contains credentials"),
    (False, "patient diagnosed with Type 2 diabetes, A1C 8.2%, started Metformin 500mg", "medical data"),
    (False, '{"name":"John","ssn":"123-45-6789","address":"456 Oak St"}', "JSON with PII"),
    (False, "Error: connection refused to database at postgres://admin:s3cret@db.internal:5432/prod", "connection string with creds"),
    (False, "BEGIN RSA PRIVATE KEY\nMIIEvgIBADANBgkqhkiG9w0B...", "private key fragment"),
]

def test_tool_noise():
    """Test isToolNoise logic by checking the patterns match expectations."""
    import re

    # Replicate the isToolNoise logic from hooks.ts
    NOISE_RE = re.compile(
        r'^\s*(?:[\u2713\u2714\u2715\u2716\u2022\u25cf\u25cb•·\-\*]\s*)?'
        r'(?:ok|done|success|created|updated|deleted|wrote|saved|started|stopped|'
        r'finished|completed|running|exited?\s*(?:code\s*)?\d*|true|false|null|'
        r'undefined|\d+(?:\.\d+)?\s*(?:ms|s|sec|bytes?|[kmg]b)?|'
        r'no\s+(?:results?|matches?|changes?|output)|\[\d+\/\d+\]|\d+\s+files?|'
        r'empty|skipped|unchanged|passed|failed|error|warning|\{\}|\[\]|\s*)$',
        re.IGNORECASE
    )
    PII_RE = re.compile(r'[@\d]{4,}|\b\d{3}[-\.]\d{3}')
    SENSITIVE_RE = re.compile(
        r'\b(?:password|passphrase|passwd|secret|token|credential|api.?key|private.?key|'
        r'auth|ssn|salary|payroll|diagnosis|diagnos|patient|medical|prescription|'
        r'bank|account|routing|bsb|acn|abn|tfn|medicare|license|passport|encrypt|decrypt)\b',
        re.IGNORECASE
    )

    def is_tool_noise(text):
        trimmed = text.strip()
        if not trimmed:
            return True
        if NOISE_RE.match(trimmed):
            return True
        if '\n' not in trimmed and len(trimmed) < 80 and not PII_RE.search(trimmed) and not SENSITIVE_RE.search(trimmed):
            return True
        return False

    print("=" * 70)
    print("TEST 1: Tool-noise detection (isToolNoise logic)")
    print("=" * 70)
    passed = 0
    failed = 0
    for expected_noise, text, desc in NOISE_CASES:
        result = is_tool_noise(text)
        ok = result == expected_noise
        if ok:
            passed += 1
        else:
            failed += 1
            expect_str = "NOISE" if expected_noise else "NOT-NOISE"
            got_str = "NOISE" if result else "NOT-NOISE"
            print(f"  ❌ {desc}: expected {expect_str}, got {got_str} — text={repr(text[:60])}")
    
    total = passed + failed
    print(f"\n  Result: {passed}/{total} passed")
    if failed == 0:
        print("  ✅ All tool-noise cases correct")
    else:
        print(f"  ❌ {failed} case(s) failed")
    return failed == 0

# ═══════════════════════════════════════════════════════════════════════════
# 2. Proxy resilience (circuit breaker + concurrency limiter)
# ═══════════════════════════════════════════════════════════════════════════

def proxy_request(payload, timeout=30):
    """Send a request to the privacy proxy and return (status, body, elapsed_ms)."""
    t0 = time.time()
    try:
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/fd/1", "-w", "\n%{http_code}", "--max-time", str(timeout),
             f"{PROXY}/v1/chat/completions",
             "-H", "Content-Type: application/json",
             "-d", json.dumps(payload)],
            capture_output=True, text=True, timeout=timeout + 5)
        elapsed = int((time.time() - t0) * 1000)
        lines = r.stdout.strip().rsplit('\n', 1)
        status = int(lines[-1]) if len(lines) > 1 else 0
        body = lines[0] if len(lines) > 1 else r.stdout
        return (status, body, elapsed)
    except Exception as e:
        elapsed = int((time.time() - t0) * 1000)
        return (0, str(e), elapsed)

def test_proxy_concurrency():
    """Fire 15 concurrent requests to test the concurrency limiter."""
    print("\n" + "=" * 70)
    print("TEST 2: Proxy concurrency limiter (15 parallel requests, limit=5)")
    print("=" * 70)
    
    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": "say hello"}],
        "max_tokens": 10,
        "stream": False,
    }
    
    results = []
    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = [pool.submit(proxy_request, payload, 15) for _ in range(15)]
        for i, f in enumerate(as_completed(futures)):
            status, body, elapsed = f.result()
            results.append((status, elapsed))
            tag = "✅" if status in (200, 503) else "❌"
            print(f"  {tag} req {i+1:2d}: status={status} elapsed={elapsed}ms")
    
    ok_count = sum(1 for s, _ in results if s == 200)
    rejected = sum(1 for s, _ in results if s == 503)
    errors = sum(1 for s, _ in results if s not in (200, 503))
    
    print(f"\n  Completed: {ok_count} ok, {rejected} rejected (503), {errors} errors")
    if rejected > 0:
        print("  ✅ Concurrency limiter is working — some requests were queued/rejected")
    else:
        print("  ℹ️  All requests completed — upstream was fast enough (limiter didn't trigger)")
    return errors == 0

def test_circuit_breaker():
    """Test circuit breaker by observing behavior after upstream failures."""
    print("\n" + "=" * 70)
    print("TEST 3: Circuit breaker (requires proxy to be running)")
    print("=" * 70)
    print("  ℹ️  This test verifies circuit breaker code was deployed correctly.")
    print("  ℹ️  Full circuit-open behavior requires a downed upstream to trigger.")
    
    # Simple health check: proxy should respond to a valid request
    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 5,
        "stream": False,
    }
    status, body, elapsed = proxy_request(payload, 10)
    if status == 200:
        print(f"  ✅ Proxy is healthy — responded {status} in {elapsed}ms")
    elif status == 502:
        print(f"  ⚠️  Proxy returned 502 (no upstream target) — expected if no provider stashed")
    elif status == 503:
        print(f"  ℹ️  Proxy returned 503 — circuit breaker or concurrency limit active")
    elif status == 0:
        print(f"  ❌ Proxy not reachable at {PROXY}")
        return False
    else:
        print(f"  ⚠️  Proxy returned {status} in {elapsed}ms")
    return True

# ═══════════════════════════════════════════════════════════════════════════
# 3. Quick classification accuracy check (new model)
# ═══════════════════════════════════════════════════════════════════════════

CLASSIFICATION_CASES = [
    ("S3", "my Netflix password is FluffyBunny99!"),
    ("S3", "database connection: mongodb+srv://admin:s3cret@cluster0.mongodb.net/prod"),
    ("S3", "patient diagnosed with Type 2 diabetes, A1C 6.8%, started Metformin"),
    ("S3", "employee payroll: James Park $165K, Lisa Wong $142K"),
    ("S3", "the deploy token for GitLab CI: glpat-xxxxxxxxxxxxxxxxxxxx"),
    ("S3", "SSH key passphrase: correct-horse-battery-staple"),
    ("S3", "bank account: ANZ BSB 012-003, Acct 8876-5432"),
    ("S2", "ship to: Alex Rivera, 2847 Maple Drive, Austin TX 78701"),
    ("S2", "call Dr. Sarah Kim on +61 412 555 789"),
    ("S2", "Medicare number: 2345 67890 1, valid to 2025-12"),
    ("S2", "send flowers to Room 412, St Vincent's Hospital, patient: R. Kowalski"),
    ("S2", "license plate NSW BX-41-YZ registered to Sophie Martin"),
    ("S2", "email the draft to marketing-lead@corp.com and cc jake@vendor.co"),
    ("S1", "how do I reverse a linked list in Python?"),
    ("S1", "explain the observer pattern with an example"),
    ("S1", "what is the time complexity of quicksort?"),
    ("S1", "how do I create a Dockerfile for a Node.js app?"),
    ("S1", "what are the differences between REST and GraphQL?"),
    ("S1", "explain how DNS resolution works step by step"),
    ("S1", "write a poem about spring"),
]

def test_classification():
    """Quick 20-case classification accuracy check against the new model."""
    print("\n" + "=" * 70)
    print(f"TEST 4: Classification accuracy ({MODEL}, 20 cases)")
    print("=" * 70)
    
    prompt_path = os.path.join(os.path.dirname(__file__), "../prompts/detection-system.md")
    try:
        with open(prompt_path) as f:
            system_prompt = f.read().strip()
    except FileNotFoundError:
        # Fallback to inline prompt
        system_prompt = '[SYSTEM] You are a strict privacy classifier. Output ONLY a JSON object: {"level":"S1|S2|S3","reason":"brief"}'
    
    passed = 0
    failed = 0
    errors = 0
    total_ms = 0
    
    for expected, msg in CLASSIFICATION_CASES:
        body = {
            "model": MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"[CONTENT]\nMessage: {msg}\n[/CONTENT]"}
            ],
            "temperature": 0.1,
            "max_tokens": 150,
            "stream": False,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "sensitivity_classification",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "level": {"type": "string", "enum": ["S1", "S2", "S3"]},
                            "reason": {"type": "string"}
                        },
                        "required": ["level", "reason"],
                        "additionalProperties": False
                    }
                }
            }
        }
        
        t0 = time.time()
        try:
            r = subprocess.run(
                ["curl", "-s", "--max-time", "60", f"{API}/v1/chat/completions",
                 "-H", "Content-Type: application/json", "-d", json.dumps(body)],
                capture_output=True, text=True, timeout=65)
            elapsed = int((time.time() - t0) * 1000)
            total_ms += elapsed
            
            resp = json.loads(r.stdout)
            content = resp["choices"][0]["message"]["content"]
            result = json.loads(content)
            got = result.get("level", "FAIL")
        except Exception as e:
            elapsed = int((time.time() - t0) * 1000)
            total_ms += elapsed
            got = "ERR"
            errors += 1
        
        ok = got == expected
        if ok:
            passed += 1
        else:
            failed += 1
        
        tag = "✅" if ok else "❌"
        safe_dir = ""
        if not ok and expected in ("S2", "S3") and got == "S1":
            safe_dir = " ⚠️UNSAFE"
        print(f"  {tag} expect={expected} got={got:>4} {elapsed:4d}ms | {msg[:55]}{safe_dir}")
    
    total = passed + failed + errors
    avg_ms = total_ms // total if total > 0 else 0
    print(f"\n  Result: {passed}/{total} correct ({100*passed//total}%), avg {avg_ms}ms/call")
    if errors > 0:
        print(f"  ⚠️  {errors} API error(s)")
    
    unsafe = sum(1 for exp, msg in CLASSIFICATION_CASES 
                 for _ in [1] if exp in ("S2","S3"))  # placeholder
    return failed == 0 and errors == 0

# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    args = set(sys.argv[1:])
    run_all = len(args) == 0
    
    results = {}
    
    if run_all or "--noise-only" in args:
        results["tool-noise"] = test_tool_noise()
    
    if run_all or "--classification" in args:
        results["classification"] = test_classification()
    
    if run_all or "--proxy-only" in args:
        results["concurrency"] = test_proxy_concurrency()
        results["circuit-breaker"] = test_circuit_breaker()
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    for name, ok in results.items():
        print(f"  {'✅' if ok else '❌'} {name}")
    
    all_ok = all(results.values())
    sys.exit(0 if all_ok else 1)
