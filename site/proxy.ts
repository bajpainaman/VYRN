import { NextResponse, type NextRequest } from "next/server";
import slugs from "./lib/doc-slugs.json";

const KNOWN = new Set<string>(slugs);

/** An unknown chapter gets a real 404 status, not the not-found page streamed under a 200. */
export function proxy(request: NextRequest) {
  const slug = request.nextUrl.pathname.slice("/docs/".length).replace(/\/$/, "");
  if (slug && !KNOWN.has(slug)) {
    return NextResponse.rewrite(new URL("/_not-found", request.url), { status: 404 });
  }
  return NextResponse.next();
}

export const config = { matcher: "/docs/:slug" };
