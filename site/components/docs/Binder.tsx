import Link from "next/link";
import { ActiveTabIntoView } from "./ActiveTabIntoView";
import { SpecSearch } from "./SpecSearch";

type Tab = { slug: string; number: string; short: string };

/** The binder's index tabs: DESIGN.md, then chapters 00–14. */
export function Binder({ docs, current }: { docs: Tab[]; current: string }) {
  return (
    <nav aria-label="Spec chapters" data-binder className="border-b-2 border-ink bg-canary lg:border-b-0">
      <div className="lg:sticky lg:top-[var(--header-h)] lg:max-h-[calc(100dvh-var(--header-h))] lg:overflow-y-auto">
      <SpecSearch className="hidden px-4 pt-4 lg:block" />
      <ol className="flex overflow-x-auto lg:block lg:py-4">
        {docs.map((doc) => {
          const active = doc.slug === current;
          return (
            <li key={doc.slug} className="flex-none">
              <Link
                href={`/docs/${doc.slug}`}
                aria-current={active ? "page" : undefined}
                className={`flex items-baseline gap-3 whitespace-nowrap border-r-2 border-ink px-4 py-2.5 text-[15px] font-bold no-underline [font-stretch:105%] lg:border-r-0 lg:border-y-0 lg:px-5 lg:py-2 ${
                  active ? "bg-slab text-on-slab" : "hover:bg-canary-shade"
                }`}
              >
                <span className={`data w-7 text-[12px] font-semibold ${active ? "text-on-slab" : "text-ink-soft"}`}>
                  {doc.number === "D" ? "DS" : doc.number}
                </span>
                {doc.short}
              </Link>
            </li>
          );
        })}
      </ol>
      </div>
      <ActiveTabIntoView />
    </nav>
  );
}
