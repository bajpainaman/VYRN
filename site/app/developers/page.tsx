import type { Metadata } from "next";
import Link from "next/link";
import { PlainPage } from "@/components/PlainPage";
import { SITE_ORIGIN } from "@/lib/agent";
import { REPO_URL } from "@/lib/site";

export const metadata: Metadata = {
  title: "VYRN API",
  description: "The VYRN API: read the VYRN design and spec from code. Read-only JSON over HTTPS, no key, with an OpenAPI description.",
  alternates: { canonical: "/developers" },
};

export default function DevelopersPage() {
  return (
    <PlainPage title="VYRN API: read the spec from code">
      <p>
        The VYRN API is a read-only JSON API over the VYRN design and specification. It needs no key and has no state. It is
        for reading the spec: VYRN is a design, not a running venue, so there is no trading API. The full description is at{" "}
        <a href="/openapi.json">/openapi.json</a> (OpenAPI 3.1).
      </p>
      <h2 id="endpoints">Endpoints</h2>
      <ul>
        <li><code>GET /api/v1/chapters</code>: DESIGN.md and chapters 00–11, with HTML and Markdown URLs.</li>
        <li><code>GET /api/v1/chapters/{"{slug}"}</code>: one chapter&apos;s numbered sections and its full Markdown.</li>
        <li><code>GET /api/v1/search?q=&#123;words&#125;&amp;limit=&#123;1–50&#125;</code>: sections and spec IDs containing every word.</li>
        <li><code>GET /api/v1/ids/{"{id}"}</code>: where a spec ID such as <code>INV-WRITER</code> is defined.</li>
      </ul>
      <div className="code-wrap" tabIndex={0} role="region" aria-label="Example">
        <pre className="code">{`curl -s '${SITE_ORIGIN}/api/v1/search?q=deadline%20admission&limit=3'
curl -s ${SITE_ORIGIN}/api/v1/ids/INV-WRITER
curl -s -H 'Accept: text/markdown' ${SITE_ORIGIN}/docs/05-engine`}</pre>
      </div>
      <h2 id="markdown">Markdown for agents</h2>
      <p>
        Every page is also served as Markdown: send <code>Accept: text/markdown</code>, or add <code>.md</code> to a{" "}
        <code>/docs</code> URL. <a href="/llms.txt">llms.txt</a> lists every page and says when to use this site.
      </p>
      <h2 id="errors">Errors</h2>
      <p>
        Errors are JSON with one shape: <code>{`{ "error": { "code", "message", "hint", "docs" } }`}</code>. Codes are{" "}
        <code>not_found</code> (404) and <code>bad_request</code> (400). The hint says how to fix the request.
      </p>
      <h2 id="versioning">Versioning and deprecation</h2>
      <p>
        The version is in the path: <code>/api/v1</code>. Within v1, changes only add fields or endpoints; nothing is renamed or
        removed. A breaking change ships as <code>/api/v2</code> alongside v1. When a v1 endpoint is to be retired, its responses
        carry a <code>Deprecation</code> header (RFC 9745) and a <code>Sunset</code> header (RFC 8594) at least 90 days before the
        sunset date, and the change is announced in the <a href={`${REPO_URL}/releases`}>repository releases</a>. No v1 endpoint
        is deprecated today.
      </p>
      <h2 id="limits">Limits</h2>
      <p>
        Responses are static and served from Vercel&apos;s CDN, and no per-client rate limit is enforced today. Please keep
        automated traffic polite. If a limit is introduced, it will be announced here and returned in the standard{" "}
        <code>RateLimit</code> headers, with <code>Retry-After</code> on a 429.
      </p>
      <h2 id="source">Source</h2>
      <p>
        The API and this site are open source in the <a href={REPO_URL}>VYRN repository</a>. See also{" "}
        <Link href="/about">About</Link> and <Link href="/contact">Contact</Link>.
      </p>
    </PlainPage>
  );
}
