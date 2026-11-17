import "server-only";
import GithubSlugger from "github-slugger";
import { cacheLife } from "next/cache";
import type { RootContent as MdNode } from "mdast";
import { LICENSE_REQUEST_URL, LICENSE_URL, REPO_URL, SPEC_DATE, SPEC_DRAFT } from "./site";
import { getDocs, plainText, type Doc } from "./spec";

/** The one public origin. vryn.exchange redirects here, and every URL handed to agents uses it. */
export const SITE_ORIGIN = "https://www.vryn.trade";

export const SUMMARY =
  "VYRN is an exchange design with one central limit order book per instrument: a fill at most 1 µs after the order's first bit reaches the exchange NIC, 1B inbound messages a second on one book, BFT finality within 10 ms, a book that moves TYO → LDN → NYC every 8 hours, and an optional on-chain mode with 5 validators. No FPGA. Every figure is a design budget; no benchmark has run yet.";

export type Section = { number: string; title: string; url: string };

export type ChapterSummary = {
  slug: string;
  number: string;
  title: string;
  lines: number;
  url: string;
  markdown_url: string;
};

export type ChapterDetail = ChapterSummary & { sections: Section[]; markdown: string };

function summarize(doc: Doc): ChapterSummary {
  return {
    slug: doc.slug,
    number: doc.number === "D" ? "DESIGN" : doc.number,
    title: doc.title.replace(/^\d{2}\.\s*/, ""),
    lines: doc.markdown.split("\n").length,
    url: `${SITE_ORIGIN}/docs/${doc.slug}`,
    markdown_url: `${SITE_ORIGIN}/docs/${doc.slug}.md`,
  };
}

/** h2 and h3 headings with their numbers and anchors, using rehype-slug's slugger so anchors resolve. */
function sectionsOf(doc: Doc): Section[] {
  const slugger = new GithubSlugger();
  const out: Section[] = [];
  const walk = (nodes: readonly MdNode[]) => {
    for (const node of nodes) {
      if (node.type === "heading") {
        const text = plainText(node.children);
        const id = slugger.slug(text);
        const number = /^(\d+(?:\.\d+)*)\.?\s/.exec(text)?.[1];
        if ((node.depth === 2 || node.depth === 3) && number) {
          out.push({ number, title: text.slice(number.length).replace(/^\.?\s*/, ""), url: `${SITE_ORIGIN}/docs/${doc.slug}#${id}` });
        }
      } else if ("children" in node) {
        walk(node.children as MdNode[]);
      }
    }
  };
  walk(doc.tree.children);
  return out;
}

export async function getChapterSummaries(): Promise<ChapterSummary[]> {
  "use cache";
  cacheLife("max");
  return (await getDocs()).map(summarize);
}

export async function getChapterDetail(slug: string): Promise<ChapterDetail | undefined> {
  "use cache";
  cacheLife("max");
  const doc = (await getDocs()).find((d) => d.slug === slug);
  return doc ? { ...summarize(doc), sections: sectionsOf(doc), markdown: doc.markdown } : undefined;
}

/** A chapter as Markdown, with a short header saying where it came from. */
export async function chapterMarkdown(slug: string): Promise<string | undefined> {
  const detail = await getChapterDetail(slug);
  if (!detail) return undefined;
  return `<!-- ${detail.number}: ${detail.title} · ${SPEC_DRAFT}, ${SPEC_DATE} · HTML: ${detail.url} -->\n\n${detail.markdown}`;
}

function chapterList(chapters: readonly ChapterSummary[]): string {
  return chapters.map((c) => `- [${c.number} ${c.title}](${c.markdown_url}): ${c.lines.toLocaleString("en-US")} lines`).join("\n");
}

/** The homepage as Markdown: what an agent needs to decide where to read next. */
export async function landingMarkdown(): Promise<string> {
  "use cache";
  cacheLife("max");
  const docs = await getDocs();
  const design = docs.find((d) => d.slug === "design");
  if (!design) throw new Error("landingMarkdown: DESIGN.md is missing. Run `pnpm sync-spec`.");
  const lines = design.markdown.split("\n");
  const start = lines.findIndex((l) => l.startsWith("## 0."));
  const end = lines.findIndex((l, i) => i > start && l.startsWith("## "));
  if (start < 0) throw new Error("landingMarkdown: DESIGN.md has no §0");
  const sixLines = lines.slice(start + 1, end < 0 ? undefined : end).join("\n").trim();
  return `# VYRN: filled within 1 µs of the first bit

${SUMMARY}

## The answer in six lines (DESIGN.md §0)

${sixLines}

## Read the design and the spec

${chapterList(docs.map(summarize))}

## For agents

- llms.txt: ${SITE_ORIGIN}/llms.txt
- Read-only JSON API over the spec: ${SITE_ORIGIN}/openapi.json
- Every page is also served as Markdown: request it with \`Accept: text/markdown\`, or add \`.md\` to a /docs URL.

## License

Source-available under the VYRN Research and Education License 1.0 (${LICENSE_URL}). Research and education are free. Commercial or production use, and any use by a financial institution or a government body, needs written permission first: ${LICENSE_REQUEST_URL}

Source: ${REPO_URL}
`;
}

/** llms.txt: what VYRN is, when to use this site, and where everything is. */
export async function llmsTxt(): Promise<string> {
  "use cache";
  cacheLife("max");
  const chapters = await getChapterSummaries();
  return `# VYRN

> ${SUMMARY}

VYRN is a design and specification, not a running venue: there is no trading API.

## When to use

- You need VYRN's exact requirements, budgets or wire formats: the 16-byte message layout (01 §6), the 1 µs latency budget (02, DESIGN §4), finality (07).
- You are checking a claim about VYRN: find the section or spec ID that states it, and quote the number with its kind (budget, measured or vendor). No benchmark has run yet.
- You are explaining how VYRN works: the lanes, the cut and the BBO core (05), replication and Simplex finality (07), the follow-the-sun handoff (08), the on-chain mode (09).
- You are deciding whether VYRN may be used: read the license; firms and institutions need written permission first.

Do not use it for live market data, trading or order entry: none exist.

## How to call

- Find a section or spec ID: GET ${SITE_ORIGIN}/api/v1/search?q=<words> (JSON), then fetch its url.
- Read a whole chapter: GET ${SITE_ORIGIN}/docs/<slug>.md, or send Accept: text/markdown to the HTML URL.
- Resolve a spec ID: GET ${SITE_ORIGIN}/api/v1/ids/<ID>.
- DESIGN.md is the design in one document; chapters 00–11 are normative, and 01 §14 overrides any chapter.
- API guide, errors and versioning policy: ${SITE_ORIGIN}/developers

## Docs

${chapterList(chapters)}

## API (read-only, JSON, no auth)

- [VYRN API guide](${SITE_ORIGIN}/developers)
- [OpenAPI description](${SITE_ORIGIN}/openapi.json)
- [List chapters](${SITE_ORIGIN}/api/v1/chapters)
- Search sections and spec IDs: ${SITE_ORIGIN}/api/v1/search?q=deadline%20admission
- Resolve a spec ID: ${SITE_ORIGIN}/api/v1/ids/INV-WRITER

## Optional

- [Full text of DESIGN.md and every chapter](${SITE_ORIGIN}/llms-full.txt)
- [About](${SITE_ORIGIN}/about) · [Contact](${SITE_ORIGIN}/contact) · [Privacy](${SITE_ORIGIN}/privacy)
- [Source repository](${REPO_URL})
- [License](${LICENSE_URL})
`;
}

/** Everything, as one Markdown file. */
export async function llmsFullTxt(): Promise<string> {
  "use cache";
  cacheLife("max");
  const docs = await getDocs();
  return docs.map((d) => `<!-- ${SITE_ORIGIN}/docs/${d.slug} -->\n\n${d.markdown}`).join("\n\n---\n\n");
}

export type ApiErrorCode = "not_found" | "bad_request";

/** Every API error has the same shape: a code, what went wrong, and how to fix it. */
export function apiError(status: 400 | 404, code: ApiErrorCode, message: string, hint: string): Response {
  return Response.json({ error: { code, message, hint, docs: `${SITE_ORIGIN}/openapi.json` } }, { status });
}

export const MARKDOWN_HEADERS = { "Content-Type": "text/markdown; charset=utf-8", Vary: "Accept" } as const;
