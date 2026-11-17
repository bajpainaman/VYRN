import { getSearchIndex } from "@/lib/search";

/** Every section heading and spec ID across the spec, fetched by the docs search on first use. */
export async function GET() {
  return Response.json(await getSearchIndex());
}
