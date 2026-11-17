import Link from "next/link";
import { REPO_URL } from "@/lib/site";
import { ThemeToggle } from "./ThemeToggle";

const NAV = [
  { href: "/docs/design", label: "Design", wide: false },
  { href: "/docs/00-index", label: "Spec", wide: false },
  { href: "/#license", label: "License", wide: true },
] as const;

export function SiteHeader() {
  return (
    <header className="sticky top-0 z-40 h-[var(--header-h)] border-b-2 border-ink bg-canary">
      <div className="mx-auto flex h-full max-w-[1440px] items-stretch justify-between px-4 sm:px-8">
        <Link href="/" className="flex items-center gap-3 no-underline" aria-label="VYRN home">
          <span className="text-[22px] font-black sm:text-[26px] leading-none tracking-[0.02em] [font-stretch:125%]">VYRN</span>
          <span className="caption hidden text-ink-soft md:inline">Exchange design · draft 0.2</span>
        </Link>
        <nav aria-label="Main" className="flex items-stretch">
          {NAV.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className={`${item.wide ? "hidden sm:flex" : "flex"} items-center border-l-2 border-ink px-2 text-[14px] font-bold no-underline [font-stretch:112%] hover:bg-canary-shade sm:px-5 sm:text-[15px]`}
            >
              {item.label}
            </Link>
          ))}
          <a
            href={REPO_URL}
            className="flex items-center border-l-2 border-ink px-2 text-[14px] font-bold no-underline [font-stretch:112%] hover:bg-canary-shade sm:px-5 sm:text-[15px]"
          >
            GitHub
          </a>
          <ThemeToggle />
        </nav>
      </div>
    </header>
  );
}
