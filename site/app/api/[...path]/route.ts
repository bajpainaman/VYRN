import { apiError } from "@/lib/agent";

/** Unknown API paths answer in JSON, never with the HTML 404 page. */
export async function GET(request: Request) {
  const path = new URL(request.url).pathname;
  return apiError(404, "not_found", `No endpoint at ${path}.`, "See /openapi.json for the endpoints: /api/v1/chapters, /api/v1/chapters/{slug}, /api/v1/search, /api/v1/ids/{id}.");
}
