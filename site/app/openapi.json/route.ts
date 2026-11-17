import { SITE_ORIGIN, SUMMARY } from "@/lib/agent";

const error = {
  description: "Error",
  content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
};

const spec = {
  openapi: "3.1.0",
  info: {
    title: "VYRN spec API",
    version: "1.0.0",
    summary: "Read-only access to the VYRN design and specification.",
    description: `${SUMMARY}\n\nThis API serves the design document and spec chapters. VYRN is a design, not a running venue: there is no trading API.\n\nVersioning: the version is in the path (/api/v1); v1 only gains fields and endpoints. Deprecation: a retiring endpoint sends Deprecation (RFC 9745) and Sunset (RFC 8594) headers at least 90 days ahead; policy at /developers#versioning.`,
    license: { name: "VYRN Research and Education License 1.0", url: "https://github.com/bajpainaman/VYRN/blob/main/LICENSE" },
  },
  externalDocs: { description: "VYRN API guide: endpoints, errors, versioning and deprecation policy", url: `${SITE_ORIGIN}/developers` },
  servers: [{ url: SITE_ORIGIN }],
  paths: {
    "/api/v1/chapters": {
      get: {
        operationId: "listChapters",
        summary: "List DESIGN.md and spec chapters 00–11",
        description: "Use first, to find a chapter's slug.",
        responses: { "200": { description: "Chapters", content: { "application/json": { schema: { type: "object", required: ["chapters"], properties: { chapters: { type: "array", items: { $ref: "#/components/schemas/ChapterSummary" } } } } } } } },
      },
    },
    "/api/v1/chapters/{slug}": {
      get: {
        operationId: "getChapter",
        summary: "Get one chapter: its numbered sections and full Markdown",
        parameters: [{ name: "slug", in: "path", required: true, description: "Chapter slug from listChapters, e.g. 05-engine or design.", schema: { type: "string" } }],
        responses: { "200": { description: "Chapter", content: { "application/json": { schema: { $ref: "#/components/schemas/ChapterDetail" } } } }, "404": error },
      },
    },
    "/api/v1/search": {
      get: {
        operationId: "searchSpec",
        summary: "Find sections and spec IDs containing every query word",
        parameters: [
          { name: "q", in: "query", required: true, description: "Words to match, e.g. 'deadline admission' or 'INV-WRITER'.", schema: { type: "string", minLength: 1 } },
          { name: "limit", in: "query", required: false, description: "Results to return, 1–50.", schema: { type: "integer", minimum: 1, maximum: 50, default: 10 } },
        ],
        responses: { "200": { description: "Matches, best first", content: { "application/json": { schema: { type: "object", required: ["query", "results"], properties: { query: { type: "string" }, results: { type: "array", items: { $ref: "#/components/schemas/SearchResult" } } } } } } }, "400": error },
      },
    },
    "/api/v1/ids/{id}": {
      get: {
        operationId: "resolveSpecId",
        summary: "Find where a spec ID (INV-WRITER, C-NOCHIP, B3) is defined",
        parameters: [{ name: "id", in: "path", required: true, description: "Case-sensitive spec ID.", schema: { type: "string" } }],
        responses: { "200": { description: "Definition", content: { "application/json": { schema: { type: "object", required: ["id", "chapter", "url"], properties: { id: { type: "string" }, chapter: { type: "string" }, url: { type: "string", format: "uri" } } } } } }, "404": error },
      },
    },
  },
  components: {
    schemas: {
      ChapterSummary: {
        type: "object",
        required: ["slug", "number", "title", "lines", "url", "markdown_url"],
        properties: { slug: { type: "string" }, number: { type: "string" }, title: { type: "string" }, lines: { type: "integer" }, url: { type: "string", format: "uri" }, markdown_url: { type: "string", format: "uri" } },
      },
      ChapterDetail: {
        allOf: [
          { $ref: "#/components/schemas/ChapterSummary" },
          {
            type: "object",
            required: ["sections", "markdown"],
            properties: {
              sections: { type: "array", items: { type: "object", required: ["number", "title", "url"], properties: { number: { type: "string" }, title: { type: "string" }, url: { type: "string", format: "uri" } } } },
              markdown: { type: "string" },
            },
          },
        ],
      },
      SearchResult: {
        type: "object",
        required: ["text", "href", "url", "where", "kind"],
        properties: { text: { type: "string" }, href: { type: "string" }, url: { type: "string", format: "uri" }, where: { type: "string" }, kind: { type: "string", enum: ["section", "id"] } },
      },
      Error: {
        type: "object",
        required: ["error"],
        properties: { error: { type: "object", required: ["code", "message", "hint"], properties: { code: { type: "string", enum: ["not_found", "bad_request"] }, message: { type: "string" }, hint: { type: "string" }, docs: { type: "string", format: "uri" } } } },
      },
    },
  },
} as const;

export async function GET() {
  return Response.json(spec);
}
