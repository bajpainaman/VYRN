import { apiError, getChapterDetail, getChapterSummaries } from "@/lib/agent";

export async function generateStaticParams() {
  return (await getChapterSummaries()).map((c) => ({ slug: c.slug }));
}

/** One document: its numbered sections with anchors, and its full Markdown. */
export async function GET(_request: Request, { params }: RouteContext<"/api/v1/chapters/[slug]">) {
  const { slug } = await params;
  const detail = await getChapterDetail(slug);
  if (!detail) {
    const known = (await getChapterSummaries()).map((c) => c.slug).join(", ");
    return apiError(404, "not_found", `No chapter "${slug}".`, `Use one of: ${known}.`);
  }
  return Response.json(detail);
}
