import { getChapterSummaries } from "@/lib/agent";

/** Every document: DESIGN.md and chapters 00–14, with HTML and Markdown URLs. */
export async function GET() {
  return Response.json({ chapters: await getChapterSummaries() });
}
