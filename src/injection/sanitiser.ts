const REDACTION_MARKER = '[CONTENT REDACTED — POTENTIAL INJECTION]';

export function sanitiseContent(
  content: string,
  matchedPatterns: { category: string; pattern: string; match: string }[]
): string {
  let sanitised = content;

  // Sort by match length (longest first) to avoid partial replacements
  const sorted = [...matchedPatterns]
    .filter(p => p.match.length > 0)
    .sort((a, b) => b.match.length - a.match.length);

  for (const { match } of sorted) {
    // Escape regex special chars in the match
    const escaped = match.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(escaped, 'gi');
    sanitised = sanitised.replace(regex, REDACTION_MARKER);
  }

  // Collapse multiple consecutive redaction markers
  const escapedMarker = REDACTION_MARKER.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  sanitised = sanitised.replace(
    new RegExp(`(${escapedMarker}\\s*)+`, 'g'),
    REDACTION_MARKER + '\n'
  );

  return sanitised.trim();
}
