import { connection } from "next/server";
import { apiError, SITE_ORIGIN } from "@/lib/agent";
import { getSearchIndex } from "@/lib/search";
import { rank } from "@/lib/search-rank";

const MAX_LIMIT = 50;

/** Sections and spec IDs whose text contains every word of q, best matches first. */
export async function GET(request: Request) {
  await connection();
  const params = new URL(request.url).searchParams;
  const q = params.get("q")?.trim() ?? "";
  if (!q) return apiError(400, "bad_request", "Missing query parameter q.", "Pass words to match, e.g. ?q=deadline admission or ?q=INV-WRITER.");
  const limit = Number(params.get("limit") ?? 10);
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) {
    return apiError(400, "bad_request", `limit must be an integer from 1 to ${MAX_LIMIT}.`, "Omit limit for the default of 10.");
  }
  const results = rank(await getSearchIndex(), q, limit).map((r) => ({ ...r, url: `${SITE_ORIGIN}${r.href}` }));
  return Response.json({ query: q, results });
}
