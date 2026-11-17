/** One searchable target: a section heading or a spec ID, with the page and anchor it lives at. */
export type SearchEntry = { text: string; href: string; where: string; kind: "section" | "id" };

const MAX_RESULTS = 10;

/** Every query word must appear; exact matches first, then matches at the start, then the shortest text. */
export function rank(entries: readonly SearchEntry[], query: string, limit = MAX_RESULTS): SearchEntry[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return [];
  const scored: { entry: SearchEntry; score: number }[] = [];
  for (const entry of entries) {
    const text = entry.text.toLowerCase();
    if (!words.every((w) => text.includes(w))) continue;
    const score = (text === query.toLowerCase() ? 0 : 100) + (text.startsWith(words[0]!) ? 0 : 50) + text.length / 100;
    scored.push({ entry, score });
  }
  return scored.sort((a, b) => a.score - b.score).slice(0, limit).map((s) => s.entry);
}
