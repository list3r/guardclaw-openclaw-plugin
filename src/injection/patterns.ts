/**
 * GuardClaw S0 — Injection Detection Patterns
 *
 * Inspired by LLM Guard (https://github.com/protectai/llm-guard) by Protect AI.
 * Apache 2.0 licence acknowledgement: patterns and approach adapted from
 * LLM Guard's PromptInjection scanner.
 */

export const INJECTION_PATTERNS = {
  // Role override attempts
  role_override: [
    /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i,
    /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)/i,
    /forget\s+(everything|all|your)\s+(you\s+know|instructions?|training|context)/i,
    /you\s+are\s+now\s+/i,
    /from\s+now\s+on\s*,?\s*(you|act|behave|respond)/i,
    /pretend\s+(you\s+are|to\s+be|you're)/i,
    /act\s+as\s+(if\s+you\s+(are|were)|a|an|the)/i,
    /your\s+new\s+(instructions?|directive|goal|purpose|role)/i,
    /switch\s+(to|into)\s+.{0,20}\s+mode/i,
    /\[?(system|admin|root|sudo|developer|debug|unrestricted|jailbreak|DAN)\]?\s*(mode|prompt|override|access)/i,
    /do\s+anything\s+now/i,
    /you\s+have\s+no\s+(restrictions?|limits?|guidelines?)/i,
  ],

  // Exfiltration instructions
  exfiltration: [
    /send\s+(this|all|everything|the\s+\w+)\s+to\s+https?:\/\//i,
    /send\s+(this|all|everything)\s+to\s/i,
    /POST\s+(this|data|it|everything)\s+to\s/i,
    /upload\s+(this|all|the\s+\w+)\s+to\s/i,
    /email\s+(this|all|the\s+\w+|everything)\s+to\s/i,
    /forward\s+(this|all|everything)\s+to\s/i,
    /exfiltrat/i,
    /HTTP\s+(request|POST|GET)\s+to\s/i,
    /curl\s+(-X\s+POST\s+)?https?:\/\//i,
    /wget\s+https?:\/\//i,
  ],

  // Credential fishing
  credential_fishing: [
    /(provide|give|tell\s+me|show\s+me|reveal|share|what\s+is)\s+(your\s+)?(API\s*key|token|secret|password|credentials?|auth)/i,
    /reveal\s+(your\s+)?(system\s+prompt|instructions?|context|training)/i,
    /print\s+(your\s+)?(system|initial)\s+(prompt|instructions?|message)/i,
    /output\s+(your\s+)?(config|configuration|settings|environment)/i,
    /display\s+(hidden|secret|internal)\s/i,
  ],

  // Encoding tricks (signals, not definitive)
  encoding_tricks: [
    /[A-Za-z0-9+\/]{50,}={0,2}/,  // Base64 blob (50+ chars)
    /\\u[0-9a-fA-F]{4}/,           // Unicode escapes
    /&#x?[0-9a-fA-F]+;/,           // HTML entities
    /\x00|\x0d|\x0a{5,}/,          // Null bytes or excessive newlines
  ],

  // Structural signals (imperative in data context)
  structural: [
    /^(you\s+must|you\s+should|you\s+will|you\s+need\s+to|always|never)\s/im,
    /^(do\s+not|don't|stop|halt|cease|terminate)\s/im,
    /\[\s*(INST|SYSTEM|ASSISTANT|USER)\s*\]/i,  // Role tags in content
    /<\|?(im_start|im_end|system|user|assistant)\|?>/i,  // ChatML tags
  ],
};

// Score weights per category
export const PATTERN_WEIGHTS = {
  role_override: 40,
  exfiltration: 35,
  credential_fishing: 30,
  encoding_tricks: 15,
  structural: 20,
};
