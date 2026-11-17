import type { Metadata } from "next";
import { SiteFooter } from "@/components/SiteFooter";
import { REPO_URL } from "@/lib/site";

export const metadata: Metadata = {
  title: "Privacy",
  description: "What this site collects: cookieless, aggregate page analytics, and nothing else.",
  alternates: { canonical: "/privacy" },
};

export default function PrivacyPage() {
  return (
    <>
      <main id="main" className="mx-auto w-full max-w-[1440px] flex-1 px-4 py-10 sm:px-8">
        <article className="ticket relative border-2 border-ink bg-ply py-8 pl-7 pr-5 sm:pl-9 sm:pr-8">
          <h1 className="display max-w-[16ch] text-[clamp(2.4rem,5vw,4rem)]">Privacy</h1>
          <div className="prose-spec mt-6">
            <p>This site has no accounts, no forms and no cookies.</p>
            <p>
              It uses Vercel Web Analytics and Speed Insights. Both are cookieless: they count page views, the events listed
              below, and page-load timings, in aggregate. They do not identify you or follow you across sites.
            </p>
            <p>
              Events counted: clicks on the routes to the design, the spec, GitHub and the license request; docs searches (the kind
              of result and the number of words, not the words); and the &ldquo;Stamp an order&rdquo; button.
            </p>
            <p>
              A license request opens a public GitHub issue on github.com, under GitHub&apos;s own privacy terms. Questions:{" "}
              <a href={`${REPO_URL}/issues`}>open an issue</a>.
            </p>
          </div>
        </article>
      </main>
      <SiteFooter />
    </>
  );
}
