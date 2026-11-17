import type { Metadata } from "next";
import { cacheLife } from "next/cache";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { Arrow } from "@/components/Arrow";
import { Binder } from "@/components/docs/Binder";
import { SpecSearch } from "@/components/docs/SpecSearch";
import { Toc } from "@/components/docs/Toc";
import { JsonLd } from "@/components/JsonLd";
import { SiteFooter } from "@/components/SiteFooter";
import { SITE_ORIGIN } from "@/lib/agent";
import { renderNodes } from "@/lib/render";
import { getDoc, getDocs } from "@/lib/spec";
import { REPO_URL } from "@/lib/site";

export async function generateStaticParams() {
  return (await getDocs()).map((doc) => ({ slug: doc.slug }));
}

export async function generateMetadata({
  params,
}: PageProps<"/docs/[slug]">): Promise<Metadata> {
  const doc = await getDoc((await params).slug);
  return doc
    ? {
        title: doc.number === "D" ? "Design" : `${doc.number} ${doc.short}`,
        description: doc.title,
      }
    : {};
}

type DocParams = PageProps<"/docs/[slug]">["params"];

/**
 * The slug is URL data, so it is read inside a Suspense boundary. The binder and an empty sheet form the
 * App Shell that a client navigation shows at once; the chapter itself comes from the cache.
 */
export default function DocPage({ params }: PageProps<"/docs/[slug]">) {
  return (
    <>
      <Suspense fallback={<DocShell />}>
        <DocForParams params={params} />
      </Suspense>
      <SiteFooter />
    </>
  );
}

async function DocForParams({ params }: { params: DocParams }) {
  const { slug } = await params;
  if (!(await getDoc(slug))) notFound();
  return <DocSheet slug={slug} />;
}

async function DocShell() {
  const docs = await getDocs();
  return (
    <div className="mx-auto grid w-full max-w-[1440px] flex-1 grid-cols-1 lg:grid-cols-[232px_minmax(0,1fr)] xl:grid-cols-[232px_minmax(0,1fr)_248px]">
      <Binder
        docs={docs.map(({ slug, number, short }) => ({ slug, number, short }))}
        current=""
      />
      <main
        id="main"
        aria-busy="true"
        className="min-h-[60vh] min-w-0 border-ink bg-ply lg:border-x-2"
      />
    </div>
  );
}

/** One chapter, rendered once per deployment: the content never changes between builds. */
async function DocSheet({ slug }: { slug: string }) {
  "use cache";
  cacheLife("max");
  const docs = await getDocs();
  const index = docs.findIndex((d) => d.slug === slug);
  const doc = docs[index];
  if (!doc) throw new Error(`DocSheet: unknown chapter "${slug}"`);

  const { html, toc } = await renderNodes(doc.tree, doc.slug);
  const prev = docs[index - 1];
  const next = docs[index + 1];
  const lines = doc.markdown.split("\n").length;

  return (
    <div className="mx-auto grid w-full max-w-[1440px] flex-1 grid-cols-1 lg:grid-cols-[232px_minmax(0,1fr)] xl:grid-cols-[232px_minmax(0,1fr)_248px]">
      <Binder
        docs={docs.map(({ slug, number, short }) => ({ slug, number, short }))}
        current={doc.slug}
      />

      <JsonLd
        data={{
          "@context": "https://schema.org",
          "@type": "TechArticle",
          headline: doc.title.replace(/^\d{2}\.\s*/, ""),
          url: `${SITE_ORIGIN}/docs/${doc.slug}`,
          isPartOf: { "@type": "WebSite", "@id": `${SITE_ORIGIN}/#site` },
          author: { "@type": "Organization", "@id": `${SITE_ORIGIN}/#org`, name: "VYRN" },
          encoding: { "@type": "MediaObject", encodingFormat: "text/markdown", contentUrl: `${SITE_ORIGIN}/docs/${doc.slug}.md` },
          inLanguage: "en",
        }}
      />
      <main id="main" className="min-w-0 border-ink bg-ply lg:border-x-2">
        <header className="border-b-2 border-ink px-5 pb-6 pt-8 sm:px-10">
          <span className="data block text-[30px] font-semibold leading-none text-stamp">
            {doc.number === "D" ? "DESIGN.md" : doc.number}
          </span>
          <h1 className="display mt-3 max-w-[24ch] text-[clamp(2.2rem,4.4vw,3.8rem)]">
            {doc.title.replace(/^\d{2}\.\s*/, "")}
          </h1>
          <SpecSearch className="mt-5 lg:hidden" />
          <p className="data mt-4 text-[12.5px] text-ink-mute">
            {lines.toLocaleString("en-US")} lines ·{" "}
            <a href={`${REPO_URL}/blob/main/${doc.file}`}>{doc.file}</a> on
            GitHub
          </p>
        </header>

        {toc.length > 0 && (
          <details className="sticky top-[var(--header-h)] z-30 border-b-2 border-ink bg-ply px-5 py-3 sm:px-10 xl:hidden">
            <summary className="caption flex cursor-pointer list-none items-center gap-2 py-1 [&::-webkit-details-marker]:hidden">
              <Arrow className="transition-transform duration-150 [details[open]_&]:rotate-90" />
              On this sheet · {toc.filter((t) => t.depth === 2).length} sections
            </summary>
            <Toc entries={toc} compact />
          </details>
        )}

        {/* Server-rendered from the spec's Markdown; remark-rehype drops raw HTML from the source. */}
        <article className="prose-spec px-5 pb-16 pt-8 sm:px-10" dangerouslySetInnerHTML={{ __html: html }} />

        <nav
          aria-label="Chapters"
          className="grid gap-[2px] border-t-2 border-ink bg-ink sm:grid-cols-2"
        >
          {prev ? (
            <Link href={`/docs/${prev.slug}`} className="routebox bg-ply">
              <Arrow direction="left" />
              <span>
                {prev.number === "D"
                  ? "Design"
                  : `${prev.number} ${prev.short}`}
                <small>Previous</small>
              </span>
            </Link>
          ) : (
            <span className="bg-ply" />
          )}
          {next ? (
            <Link
              href={`/docs/${next.slug}`}
              className="routebox justify-end bg-ply text-right"
            >
              <span>
                {`${next.number} ${next.short}`}
                <small>Next</small>
              </span>
              <Arrow />
            </Link>
          ) : (
            <span className="bg-ply" />
          )}
        </nav>
      </main>

      <aside className="hidden xl:block" aria-label="On this sheet">
        <div className="sticky top-[var(--header-h)] max-h-[calc(100dvh-var(--header-h))] overflow-y-auto px-5 py-6">
          <div className="caption mb-3">On this sheet</div>
          <Toc entries={toc} />
        </div>
      </aside>
    </div>
  );
}
