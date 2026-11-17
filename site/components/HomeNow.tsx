"use client";

import { useEffect, useState } from "react";
import { formatDuration, homeAt, HOMES, type HomeState } from "@/lib/home";

const REFRESH_MS = 30_000;

/** The three homes as the UTC day, with the live one inked. Computed in the browser from the fixed boundaries. */
export function HomeNow() {
  const [state, setState] = useState<HomeState | null>(null);

  useEffect(() => {
    const update = () => setState(homeAt(new Date()));
    update();
    const id = window.setInterval(update, REFRESH_MS);
    return () => window.clearInterval(id);
  }, []);

  return (
    <div>
      <ol className="grid grid-cols-3 gap-[2px] border-2 border-ink bg-ink" aria-label="Homes by UTC window">
        {HOMES.map((home, i) => {
          const live = state?.home === home;
          return (
            <li key={home} className={`px-3 py-3 sm:px-4 ${live ? "bg-ink text-canary" : "bg-canary"}`}>
              <span className="block text-[36px] font-black leading-none [font-stretch:110%] sm:text-[46px]">
                {home}
              </span>
              <span className="data mt-2 block text-[12px]">
                {String(i * 8).padStart(2, "0")}:00–{String(i * 8 + 8).padStart(2, "0")}:00 UTC
              </span>
              <span className={`caption mt-1 block ${live ? "" : "invisible"}`}>{live ? "Home now" : "—"}</span>
            </li>
          );
        })}
      </ol>
      <p className="mt-3 text-[14px] text-ink-soft">
        {state
          ? `Next handoff: ${state.home} → ${state.next} at ${String(state.nextBoundaryUtc).padStart(2, "0")}:00 UTC, in ${formatDuration(state.msToHandoff)}.`
          : "Reading the UTC clock."}
      </p>
    </div>
  );
}
