import { chapterMarkdown, getChapterSummaries, landingMarkdown, MARKDOWN_HEADERS } from "@/lib/agent";

export async function generateStaticParams() {
  return [{ slug: [] }, ...(await getChapterSummaries()).map((c) => ({ slug: ["docs", c.slug] }))];
}

/**
 * Markdown versions of the pages. The proxy routes "Accept: text/markdown" requests for / and
 * /docs/<slug> here, and next.config rewrites /docs/<slug>.md here too.
 */
export async function GET(_request: Request, { params }: RouteContext<"/md/[[...slug]]">) {
  const { slug = [] } = await params;
  if (slug.length === 0) return new Response(await landingMarkdown(), { headers: MARKDOWN_HEADERS });
  const markdown = slug[0] === "docs" && slug.length === 2 ? await chapterMarkdown(slug[1]!) : undefined;
  if (!markdown) {
    return new Response(`# Not found\n\nNo page at /${slug.join("/")}. Start at /llms.txt for the list of pages.\n`, { status: 404, headers: MARKDOWN_HEADERS });
  }
  return new Response(markdown, { headers: MARKDOWN_HEADERS });
}
