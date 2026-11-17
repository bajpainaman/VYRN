"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { track } from "@vercel/analytics";
import { rank, type SearchEntry } from "@/lib/search-rank";

export { rank, type SearchEntry };

type Status = "idle" | "loading" | "ready" | "error";

/** Find a section or a spec ID anywhere in the spec. "/" focuses it from anywhere on a docs page. */
export function SpecSearch({ className = "" }: { className?: string }) {
  const router = useRouter();
  const inputId = useId();
  const listId = useId();
  const input = useRef<HTMLInputElement>(null);
  const [entries, setEntries] = useState<SearchEntry[]>([]);
  const [status, setStatus] = useState<Status>("idle");
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);

  const load = useCallback(async () => {
    if (status !== "idle") return;
    setStatus("loading");
    try {
      const response = await fetch("/search-index.json");
      if (!response.ok) throw new Error(`search index: HTTP ${response.status}`);
      setEntries((await response.json()) as SearchEntry[]);
      setStatus("ready");
    } catch (error) {
      console.error(error);
      setStatus("error");
    }
  }, [status]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const typing = target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);
      if (event.key === "/" && !typing && input.current?.offsetParent) {
        event.preventDefault();
        input.current.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const results = useMemo(() => rank(entries, query), [entries, query]);
  const open = query.trim().length > 0;

  const go = (entry: SearchEntry | undefined) => {
    if (!entry) return;
    track("docs_search", { kind: entry.kind, where: entry.where, words: query.trim().split(/\s+/).length });
    setQuery("");
    input.current?.blur();
    router.push(entry.href);
  };

  return (
    <div className={`relative ${className}`}>
      <label htmlFor={inputId} className="sr-only">
        Find a section or spec ID
      </label>
      <input
        ref={input}
        id={inputId}
        type="search"
        role="combobox"
        aria-expanded={open}
        aria-controls={listId}
        aria-activedescendant={open && results[active] ? `${listId}-${active}` : undefined}
        autoComplete="off"
        spellCheck={false}
        placeholder="Find a section or ID   /"
        value={query}
        onFocus={load}
        onChange={(e) => {
          setQuery(e.target.value);
          setActive(0);
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setActive((i) => Math.min(i + 1, Math.max(results.length - 1, 0)));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActive((i) => Math.max(i - 1, 0));
          } else if (e.key === "Enter") {
            e.preventDefault();
            go(results[active]);
          } else if (e.key === "Escape") {
            setQuery("");
          }
        }}
        className="w-full border-2 border-ink bg-ply px-3 py-2 text-[14px] placeholder:text-ink-mute focus:outline-none focus-visible:outline-2 focus-visible:outline-offset-3 focus-visible:outline-stamp"
      />
      {open && (
        <ul
          id={listId}
          role="listbox"
          aria-label="Matches"
          className="absolute left-0 top-full z-50 mt-1 max-h-[60vh] w-full min-w-[min(380px,calc(100vw-2rem))] overflow-y-auto border-2 border-ink bg-ply shadow-[0_14px_30px_-18px_rgba(25,27,38,0.6)]"
        >
          {status === "loading" && <li className="px-3 py-2 text-[14px] text-ink-mute">Loading the index…</li>}
          {status === "error" && (
            <li className="px-3 py-2 text-[14px] text-ink">The search index did not load. Reload the page to try again.</li>
          )}
          {status === "ready" && results.length === 0 && (
            <li className="px-3 py-2 text-[14px] text-ink-mute">No section or ID matches “{query.trim()}”.</li>
          )}
          {results.map((entry, i) => (
            <li
              key={entry.href}
              id={`${listId}-${i}`}
              role="option"
              aria-selected={i === active}
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => go(entry)}
              onMouseEnter={() => setActive(i)}
              className={`flex cursor-pointer items-baseline justify-between gap-3 border-b border-ink/15 px-3 py-2 last:border-b-0 ${
                i === active ? "bg-canary" : ""
              }`}
            >
              <span className={`text-[14px] leading-snug ${entry.kind === "id" ? "data font-semibold text-stamp" : "font-semibold"}`}>
                {entry.text}
              </span>
              <span className="data flex-none text-[11.5px] text-ink-mute">{entry.where}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
