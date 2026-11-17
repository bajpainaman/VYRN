import { NextResponse, type NextRequest } from "next/server";
import slugs from "./lib/doc-slugs.json";

const KNOWN = new Set<string>(slugs);

/** Media types the client asked for, ordered by quality (RFC 9110 §12.5.1), types with q=0 dropped. */
function accepted(header: string | null): string[] {
  if (!header) return [];
  return header
    .split(",")
    .map((part, order) => {
      const [type = "", ...params] = part.trim().split(";");
      const q = Number(params.find((p) => p.trim().startsWith("q="))?.split("=")[1] ?? 1);
      return { type: type.trim().toLowerCase(), q: Number.isFinite(q) ? q : 0, order };
    })
    .filter((a) => a.q > 0)
    .sort((a, b) => b.q - a.q || a.order - b.order)
    .map((a) => a.type);
}

/** Markdown wins when the client ranks text/markdown above text/html (or asks only for Markdown). */
function wantsMarkdown(types: string[]): boolean {
  const md = types.indexOf("text/markdown");
  const html = types.indexOf("text/html");
  return md >= 0 && (html < 0 || md < html);
}

function wantsJson(types: string[]): boolean {
  const json = types.indexOf("application/json");
  const html = types.indexOf("text/html");
  return json >= 0 && (html < 0 || json < html);
}

/**
 * One URL, three readers: browsers get HTML, agents asking for text/markdown get Markdown, and an
 * unknown chapter answers 404 in whichever of HTML, Markdown or JSON the client asked for.
 */
export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const types = accepted(request.headers.get("accept"));

  let slug: string | undefined;
  let explicitMarkdown = false;
  if (pathname.startsWith("/docs/")) {
    slug = pathname.slice("/docs/".length).replace(/\/$/, "");
    if (slug.endsWith(".md")) {
      slug = slug.slice(0, -".md".length);
      explicitMarkdown = true;
    }
    if (!KNOWN.has(slug)) {
      if (wantsJson(types)) {
        return NextResponse.json(
          { error: { code: "not_found", message: `No chapter "${slug}".`, hint: `Use one of: ${[...KNOWN].join(", ")}.`, docs: "/openapi.json" } },
          { status: 404 },
        );
      }
      if (explicitMarkdown || wantsMarkdown(types)) {
        return new NextResponse(`# Not found\n\nNo chapter "${slug}". Start at /llms.txt for the list of pages.\n`, {
          status: 404,
          headers: { "Content-Type": "text/markdown; charset=utf-8", Vary: "Accept" },
        });
      }
      return NextResponse.rewrite(new URL("/_not-found", request.url), { status: 404 });
    }
  }

  if (explicitMarkdown || wantsMarkdown(types)) {
    return NextResponse.rewrite(new URL(slug ? `/md/docs/${slug}` : "/md", request.url));
  }
  const response = NextResponse.next();
  response.headers.append("Vary", "Accept");
  return response;
}

export const config = { matcher: ["/", "/docs/:slug"] };
