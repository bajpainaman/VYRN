"use client";

import { useEffect, useState } from "react";
import type { TocEntry } from "@/lib/spec";

/** Section list with the section under the reading line marked. */
export function Toc({ entries, compact = false }: { entries: TocEntry[]; compact?: boolean }) {
  const [active, setActive] = useState<string | null>(null);

  useEffect(() => {
    if (compact) return;
    const headings = entries
      .map((e) => document.getElementById(e.id))
      .filter((el): el is HTMLElement => el !== null);
    const observer = new IntersectionObserver(
      (records) => {
        const visible = records.filter((r) => r.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActive(visible[0].target.id);
      },
      // The reading line sits just under the sticky header.
      { rootMargin: "-72px 0px -70% 0px" },
    );
    headings.forEach((h) => observer.observe(h));
    return () => observer.disconnect();
  }, [entries, compact]);

  return (
    <ol className={`text-[13.5px] leading-snug ${compact ? "mt-2 grid max-h-[60vh] gap-1 overflow-y-auto pb-2" : "grid gap-0.5"}`}>
      {entries.map((entry) => (
        <li key={entry.id} className={entry.depth === 3 ? "pl-3" : ""}>
          <a
            href={`#${entry.id}`}
            onClick={compact ? (e) => e.currentTarget.closest("details")?.removeAttribute("open") : undefined}
            aria-current={active === entry.id ? "location" : undefined}
            className={`block py-1 no-underline hover:underline ${
              entry.depth === 2 ? "font-bold" : "text-ink-soft"
            } ${active === entry.id ? "text-stamp" : ""}`}
          >
            {entry.text}
          </a>
        </li>
      ))}
    </ol>
  );
}
