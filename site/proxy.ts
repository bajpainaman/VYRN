import { NextResponse, type NextRequest } from "next/server";
import slugs from "./lib/doc-slugs.json";

const KNOWN = new Set<string>(slugs);

/** Paths the site serves outside /docs; anything else is a 404. */
const SERVED = ["/about", "/contact", "/developers", "/privacy", "/api", "/md", "/security-txt", "/search-index.json", "/openapi.json", "/llms.txt", "/llms-full.txt", "/sitemap.xml", "/robots.txt", "/icon.svg", "/og.png", "/diagrams", "/.well-known/security.txt", "/docs", "/_not-found"];

const NOT_FOUND_MARKDOWN = (path: string) =>
  `# Not found (404)\n\nThere is no page at \`${path}\` on this site.\n\n- Every page, with Markdown links: [llms.txt](https://www.vryn.trade/llms.txt)\n- The spec index: [/docs/00-index.md](https://www.vryn.trade/docs/00-index.md)\n- The read-only API: [openapi.json](https://www.vryn.trade/openapi.json)\n- Sitemap: [sitemap.xml](https://www.vryn.trade/sitemap.xml)\n`;

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
export { accepted, wantsMarkdown };

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const types = accepted(request.headers.get("accept"));

  let slug: string | undefined;
  let explicitMarkdown = false;
  if (pathname.startsWith("/docs/")) {
    slug = pathname.slice("/docs/".length).replace(/\/$/, "");
    // Files under a chapter (its share image) are Next's to serve.
    if (slug.includes("/")) return NextResponse.next();
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
        return new NextResponse(NOT_FOUND_MARKDOWN(pathname), {
          status: 404,
          headers: { "Content-Type": "text/markdown; charset=utf-8", Vary: "Accept" },
        });
      }
      return NextResponse.rewrite(new URL("/_not-found", request.url), { status: 404 });
    }
  }

  // Any other path the site does not serve: agents asking for Markdown or JSON get a 404 they can read.
  if (!slug && pathname !== "/" && !SERVED.some((p) => pathname === p || pathname.startsWith(`${p}/`))) {
    if (wantsJson(types)) {
      return NextResponse.json(
        { error: { code: "not_found", message: `No page at ${pathname}.`, hint: "See /llms.txt for every page and /openapi.json for the API.", docs: "/llms.txt" } },
        { status: 404 },
      );
    }
    if (wantsMarkdown(types)) {
      return new NextResponse(NOT_FOUND_MARKDOWN(pathname), { status: 404, headers: { "Content-Type": "text/markdown; charset=utf-8", Vary: "Accept" } });
    }
    return NextResponse.next();
  }

  // Only the homepage and the chapters have Markdown versions; other pages stay HTML.
  if ((slug || pathname === "/") && (explicitMarkdown || wantsMarkdown(types))) {
    return NextResponse.rewrite(new URL(slug ? `/md/docs/${slug}` : "/md", request.url));
  }
  const response = NextResponse.next();
  response.headers.append("Vary", "Accept");
  return response;
}

// Every path except Next's own assets, Vercel's scripts and static files the site ships.
export const config = { matcher: ["/((?!_next/|_vercel/|favicon\\.ico).*)"] };
