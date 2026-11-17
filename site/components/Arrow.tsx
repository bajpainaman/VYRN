/** A plain routing arrow, drawn to match the tick's stroke. */
export function Arrow({ direction = "right", className = "" }: { direction?: "left" | "right"; className?: string }) {
  return (
    <svg width="18" height="14" viewBox="0 0 18 14" aria-hidden focusable="false" className={`${direction === "left" ? "-scale-x-100" : ""} ${className}`}>
      <path d="M1 7h14M10 1.5 15.5 7 10 12.5" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="square" />
    </svg>
  );
}
