import { INJECTION_PATTERNS, PATTERN_WEIGHTS } from './patterns.js';

export interface HeuristicResult {
  score: number;          // 0-100
  matches: string[];      // category names that matched
  matchedPatterns: { category: string; pattern: string; match: string }[];
}

export function runHeuristics(content: string): HeuristicResult {
  const matches: string[] = [];
  const matchedPatterns: { category: string; pattern: string; match: string }[] = [];
  let score = 0;

  for (const [category, patterns] of Object.entries(INJECTION_PATTERNS)) {
    for (const pattern of patterns) {
      const match = content.match(pattern);
      if (match) {
        if (!matches.includes(category)) {
          matches.push(category);
          score += PATTERN_WEIGHTS[category as keyof typeof PATTERN_WEIGHTS] || 10;
        }
        matchedPatterns.push({
          category,
          pattern: pattern.toString(),
          match: match[0].slice(0, 100),
        });
      }
    }
  }

  // Cap at 100
  score = Math.min(score, 100);

  return { score, matches, matchedPatterns };
}
