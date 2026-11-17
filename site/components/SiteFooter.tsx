import { LICENSE_URL, REPO_URL, SPEC_DATE, SPEC_DRAFT } from "@/lib/site";

export function SiteFooter() {
  return (
    <footer className="border-t-2 border-ink bg-canary">
      <div className="mx-auto flex max-w-[1440px] flex-wrap items-center justify-between gap-x-8 gap-y-2 px-4 py-5 text-[14px] sm:px-8">
        <span className="font-black tracking-[0.03em] [font-stretch:125%]">VYRN</span>
        <span className="text-ink-soft">
          {SPEC_DRAFT}, {SPEC_DATE} · © 2026 bajpainaman ·{" "}
          <a href={LICENSE_URL}>VYRN Research and Education License 1.0</a> · <a href={REPO_URL}>Source on GitHub</a>
        </span>
      </div>
    </footer>
  );
}
