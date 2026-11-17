import { apiError, SITE_ORIGIN } from "@/lib/agent";
import { getIdIndex } from "@/lib/spec";

export async function generateStaticParams() {
  return Object.keys(await getIdIndex()).map((id) => ({ id }));
}

/** Where a spec ID (INV-WRITER, C-NOCHIP, B3) is defined. */
export async function GET(_request: Request, { params }: RouteContext<"/api/v1/ids/[id]">) {
  const { id } = await params;
  const owner = (await getIdIndex())[id];
  if (!owner) return apiError(404, "not_found", `No spec ID "${id}".`, "IDs are case-sensitive. Search with /api/v1/search?q=<words>.");
  return Response.json({ id, chapter: owner, url: `${SITE_ORIGIN}/docs/${owner}#id-${id}` });
}
