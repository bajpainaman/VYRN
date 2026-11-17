/** The follow-the-sun schedule from spec 08 §2: fixed UTC boundaries, home = [TYO, LDN, NYC][e mod 3]. */
export const HOMES = ["TYO", "LDN", "NYC"] as const;
export type Home = (typeof HOMES)[number];

const EPOCH_MS = 8 * 60 * 60 * 1000;
const DAY_MS = 3 * EPOCH_MS;

export type HomeState = {
  home: Home;
  next: Home;
  /** UTC hour of the next boundary: 0, 8 or 16. */
  nextBoundaryUtc: 0 | 8 | 16;
  msToHandoff: number;
  /** Position in the UTC day, 0 to 1. */
  dayFraction: number;
};

export function homeAt(now: Date): HomeState {
  const ms = now.getTime();
  const intoDay = ((ms % DAY_MS) + DAY_MS) % DAY_MS;
  const slot = Math.floor(intoDay / EPOCH_MS) as 0 | 1 | 2;
  const nextSlot = ((slot + 1) % 3) as 0 | 1 | 2;
  return {
    home: HOMES[slot],
    next: HOMES[nextSlot],
    nextBoundaryUtc: ([0, 8, 16] as const)[nextSlot],
    msToHandoff: EPOCH_MS - (intoDay % EPOCH_MS),
    dayFraction: intoDay / DAY_MS,
  };
}

export function formatDuration(ms: number): string {
  const totalMinutes = Math.max(0, Math.floor(ms / 60000));
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return `${hours} h ${String(minutes).padStart(2, "0")} m`;
}
