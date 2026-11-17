import "server-only";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import GithubSlugger from "github-slugger";
import { cacheLife } from "next/cache";
import type { Root as MdRoot, RootContent as MdNode, Heading, PhrasingContent } from "mdast";
import remarkParse from "remark-parse";
import remarkGfm from "remark-gfm";
import { unified } from "unified";

const CONTENT_DIR = path.join(process.cwd(), "content");

/** A document the site renders: DESIGN.md or one spec chapter. */
export type Doc = {
  slug: string;
  /** Two-digit chapter number, or "D" for DESIGN.md. */
  number: string;
  title: string;
  /** Short label for the binder tab. */
  short: string;
  file: string;
  markdown: string;
  tree: MdRoot;
};

export type TocEntry = { depth: 2 | 3; text: string; id: string };

const parser = unified().use(remarkParse).use(remarkGfm);

export function parseMarkdown(markdown: string): MdRoot {
  return parser.parse(markdown);
}

/** Plain text of mdast phrasing content, without markup. */
export function plainText(nodes: readonly (MdNode | PhrasingContent)[]): string {
  return nodes
    .map((node) => {
      if ("value" in node && typeof node.value === "string") return node.value;
      if ("children" in node) return plainText(node.children as MdNode[]);
      return "";
    })
    .join("");
}

function titleOf(tree: MdRoot, fallback: string): string {
  const h1 = tree.children.find((n): n is Heading => n.type === "heading" && n.depth === 1);
  return h1 ? plainText(h1.children) : fallback;
}

// Binder-tab labels. The chapter titles are long; the tab only has room for one word.
const SHORT_LABELS: Record<string, string> = {
  design: "Design",
  "00-index": "Index",
  "01-conventions": "Conventions",
  "02-requirements": "Requirements",
  "03-architecture": "Architecture",
  "04-protocol": "Protocol",
  "05-engine": "Engine",
  "06-platform": "Platform",
  "07-replication": "Replication",
  "08-epochs": "Epochs",
  "09-chain": "Chain",
  "10-accounts-risk-md": "Accounts & risk",
  "11-build": "Build",
  "12-commitment": "Commitment",
  "13-availability": "Availability",
  "14-envelope": "Envelope",
};

async function loadDoc(file: string, slug: string, number: string): Promise<Doc> {
  const markdown = await readFile(path.join(CONTENT_DIR, file), "utf8");
  const tree = parseMarkdown(markdown);
  return {
    slug,
    number,
    file,
    markdown,
    tree,
    title: titleOf(tree, slug),
    short: SHORT_LABELS[slug] ?? slug,
  };
}

/** Content is synced into the repo before each build, so it never changes inside a deployment. */
export async function getDocs(): Promise<Doc[]> {
  "use cache";
  cacheLife("max");
  const chapterFiles = (await readdir(path.join(CONTENT_DIR, "spec")))
    .filter((name) => /^\d{2}-.+\.md$/.test(name))
    .sort();
  if (chapterFiles.length === 0) {
    throw new Error(`No spec chapters in ${CONTENT_DIR}/spec. Run \`pnpm sync-spec\`.`);
  }
  const design = loadDoc("DESIGN.md", "design", "D");
  const chapters = chapterFiles.map((name) =>
    loadDoc(path.join("spec", name), name.replace(/\.md$/, ""), name.slice(0, 2)),
  );
  return Promise.all([design, ...chapters]);
}

export async function getDoc(slug: string): Promise<Doc | undefined> {
  return (await getDocs()).find((doc) => doc.slug === slug);
}

/** Maps a Markdown link target inside the spec to a site route. */
export function resolveSpecHref(href: string): string {
  if (/^[a-z]+:/i.test(href) || href.startsWith("#") || href.startsWith("/")) return href;
  const [target, hash] = href.split("#");
  const file = path.posix.basename(target ?? "");
  const anchor = hash ? `#${hash}` : "";
  if (file === "DESIGN.md") return `/docs/design${anchor}`;
  if (/^\d{2}-.+\.md$/.test(file)) return `/docs/${file.replace(/\.md$/, "")}${anchor}`;
  if (file === "" || file === "spec") return `/docs/00-index${anchor}`;
  return `https://github.com/bajpainaman/VYRN/blob/main/${target}${anchor}`;
}

// A spec ID: hyphenated caps (C-NOCHIP, INV-WRITER, R-INDEX) or a benchmark number (B3).
const GLOBAL_ID = /^(?:[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+|B\d{1,2})$/;

/** The first-cell ID of a table row, when the row defines one. */
export function rowId(cellText: string): string | undefined {
  const text = cellText.replace(/\*/g, "").trim();
  return /^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*\d*$/.test(text) && text.length >= 2 && text !== "ID"
    ? text
    : undefined;
}

/**
 * Spec IDs mapped to the document that defines them. Short IDs (P3, S1) repeat across chapters as
 * local labels, so only global IDs are cross-linked, and an ID claimed by several chapters links
 * only when one of them is the binding definition.
 */
export async function getIdIndex(): Promise<Readonly<Record<string, string>>> {
  "use cache";
  cacheLife("max");
  const owners = new Map<string, Set<string>>();
  for (const doc of await getDocs()) {
    for (const node of doc.tree.children) {
      if (node.type !== "table") continue;
      for (const row of node.children.slice(1)) {
        const first = row.children[0];
        const id = first ? rowId(plainText(first.children)) : undefined;
        if (!id || !GLOBAL_ID.test(id)) continue;
        const set = owners.get(id) ?? new Set<string>();
        set.add(doc.slug);
        owners.set(id, set);
      }
    }
  }
  const index: Record<string, string> = {};
  for (const [id, slugs] of owners) {
    // When an ID labels rows in several chapters, the binding definition wins: 00-index for the hard
    // constraints (C-*), otherwise 01-conventions, "the contract every chapter follows".
    const list = [...slugs];
    if (list.length === 1) index[id] = list[0]!;
    else if (list.includes("00-index") && id.startsWith("C-")) index[id] = "00-index";
    else if (list.includes("01-conventions")) index[id] = "01-conventions";
  }
  return index;
}

/** The nodes of a DESIGN.md section: everything after the h2 whose text starts with `prefix`, up to the next h2. */
export function sectionNodes(tree: MdRoot, prefix: string): MdNode[] {
  const start = tree.children.findIndex(
    (n) => n.type === "heading" && n.depth === 2 && plainText(n.children).startsWith(prefix),
  );
  if (start < 0) throw new Error(`DESIGN.md has no section starting with "${prefix}"`);
  const rest = tree.children.slice(start + 1);
  const end = rest.findIndex((n) => n.type === "heading" && n.depth <= 2);
  return end < 0 ? rest : rest.slice(0, end);
}

/** A chapter's numbered sections ("6.2", "14") mapped to the heading ids the renderer gives them. */
export type SectionIndex = Readonly<Record<string, Readonly<Record<string, string>>>>;

const SECTION_NUMBER = /^(\d+(?:\.\d+)*)\.?\s/;

/**
 * Section numbers per document, using the same slugger as rehype-slug (one per document, every
 * heading in order) so a "§6.8" link lands on the id the page actually carries.
 */
export async function getSectionIndex(): Promise<SectionIndex> {
  "use cache";
  cacheLife("max");
  const out: Record<string, Record<string, string>> = {};
  for (const doc of await getDocs()) {
    const slugger = new GithubSlugger();
    const sections: Record<string, string> = {};
    visitHeadings(doc.tree, (text) => {
      const id = slugger.slug(text);
      const number = SECTION_NUMBER.exec(text)?.[1];
      if (number && !(number in sections)) sections[number] = id;
    });
    out[doc.slug] = sections;
  }
  return out;
}

function visitHeadings(tree: MdRoot, onHeading: (text: string) => void): void {
  const walk = (nodes: readonly MdNode[]) => {
    for (const node of nodes) {
      if (node.type === "heading") onHeading(plainText(node.children));
      else if ("children" in node) walk(node.children as MdNode[]);
    }
  };
  walk(tree.children);
}

/** "01" → "01-conventions", plus "DESIGN" → "design". */
export async function getChapterSlugs(): Promise<Readonly<Record<string, string>>> {
  const map: Record<string, string> = { DESIGN: "design" };
  for (const doc of await getDocs()) if (doc.number !== "D") map[doc.number] = doc.slug;
  return map;
}
