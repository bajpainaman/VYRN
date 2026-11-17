import "server-only";
import GithubSlugger from "github-slugger";
import type { Code, List, ListItem, Paragraph, PhrasingContent, RootContent, Table } from "mdast";
import { EXIT, visit } from "unist-util-visit";
import { getDoc, plainText, sectionNodes, type Doc } from "./spec";

/**
 * Structured reads of DESIGN.md for the landing page. Every value comes from the document at
 * build time, so the page cannot drift from the design it presents.
 */

async function requireDoc(slug: string): Promise<Doc> {
  const doc = await getDoc(slug);
  if (!doc) throw new Error(`Missing document "${slug}". Run \`pnpm sync-spec\`.`);
  return doc;
}

function first<T extends RootContent["type"]>(nodes: RootContent[], type: T, where: string): Extract<RootContent, { type: T }> {
  const node = nodes.find((n) => n.type === type);
  if (!node) throw new Error(`DESIGN.md ${where}: expected a ${type}`);
  return node as Extract<RootContent, { type: T }>;
}

/** Rows of a GFM table as plain-text cells, header row excluded. */
function tableRows(table: Table): string[][] {
  return table.children.slice(1).map((row) => row.children.map((cell) => plainText(cell.children).trim()));
}

/** Splits a list item into its bold lead and the paragraph that follows it. */
function leadAndBody(item: ListItem): { lead: string; body: Paragraph } {
  const para = item.children.find((c): c is Paragraph => c.type === "paragraph");
  if (!para) throw new Error("DESIGN.md: list item without a paragraph");
  const [head, ...rest] = para.children;
  if (head?.type !== "strong") return { lead: "", body: para };
  const trimmed: PhrasingContent[] = [...rest];
  const firstText = trimmed[0];
  if (firstText?.type === "text") trimmed[0] = { ...firstText, value: firstText.value.replace(/^\s+/, "") };
  return { lead: plainText(head.children), body: { type: "paragraph", children: trimmed } };
}

/** Site route to a DESIGN.md heading, using the same slugs the docs renderer gives it. */
export async function designHref(prefix: string): Promise<string> {
  const doc = await requireDoc("design");
  const slugger = new GithubSlugger();
  for (const node of doc.tree.children) {
    if (node.type !== "heading") continue;
    const text = plainText(node.children);
    const slug = slugger.slug(text);
    if (text.startsWith(prefix)) return `/docs/design#${slug}`;
  }
  throw new Error(`DESIGN.md has no heading starting with "${prefix}"`);
}

export type Line = { lead: string; body: Paragraph };

export async function getSixLines(): Promise<Line[]> {
  const nodes = sectionNodes((await requireDoc("design")).tree, "0.");
  const list = first(nodes, "list", "§0") as List;
  return list.children.map(leadAndBody);
}

export type ShareRow = { message: string; handledBy: string; share: number };

export async function getMessageShares(): Promise<ShareRow[]> {
  const nodes = sectionNodes((await requireDoc("design")).tree, "3.");
  const rows = tableRows(first(nodes, "table", "§3"));
  const parsed = rows.map(([message = "", , handledBy = "", share = ""]) => ({
    message,
    handledBy,
    share: Number.parseFloat(share.replace(/[^\d.]/g, "")),
  }));
  const total = parsed.reduce((sum, r) => sum + r.share, 0);
  if (parsed.some((r) => !Number.isFinite(r.share)) || Math.round(total) !== 100) {
    throw new Error(`DESIGN.md §3: design shares must be numbers that add to 100 (got ${total})`);
  }
  return parsed;
}

export type CompareRow = { axis: string; best: string; spec: string };

export async function getComparison(): Promise<CompareRow[]> {
  const nodes = sectionNodes((await requireDoc("design")).tree, "1.");
  return tableRows(first(nodes, "table", "§1")).map(([axis = "", best = "", spec = ""]) => ({ axis, best, spec }));
}

export type HandoffRow = { handoff: string; wan: string; window: string };

export async function getHandoffs(): Promise<HandoffRow[]> {
  const nodes = sectionNodes((await requireDoc("design")).tree, "6.");
  return tableRows(first(nodes, "table", "§6")).map(([handoff = "", wan = "", window = ""]) => ({ handoff, wan, window }));
}

export type BenchRow = { id: string; test: string; pass: string };

export async function getWeekOneTests(): Promise<BenchRow[]> {
  const nodes = sectionNodes((await requireDoc("design")).tree, "9.");
  return tableRows(first(nodes, "table", "§9")).map(([id = "", test = "", pass = ""]) => ({ id, test, pass }));
}

export async function getGrilling(): Promise<Line[]> {
  const nodes = sectionNodes((await requireDoc("design")).tree, "10.");
  return (first(nodes, "list", "§10") as List).children.map(leadAndBody);
}

export type AsciiBlock = { code: Code; asciiIndex: number };

/**
 * The first ASCII block after a heading in a spec chapter, verbatim, with its position among the
 * document's ASCII blocks (the key its drawn figure is filed under).
 */
export async function getAsciiAfter(slug: string, headingPrefix: string): Promise<AsciiBlock> {
  const doc = await requireDoc(slug);
  let seenHeading = false;
  let index = 0;
  let found: AsciiBlock | undefined;
  visit(doc.tree, (node) => {
    if (found) return EXIT;
    if (node.type === "heading" && plainText(node.children).startsWith(headingPrefix)) seenHeading = true;
    if (node.type !== "code" || (node.lang && node.lang !== "text")) return;
    if (seenHeading) found = { code: node, asciiIndex: index };
    index++;
  });
  if (!found) throw new Error(`${doc.file}: no ASCII block after "${headingPrefix}"`);
  return found;
}

export type GlossaryEntry = { term: string; meaning: Paragraph };

/** Terms from 01 §1 ("Words"), in the order asked for. Fails the build if a term disappears. */
export async function getGlossary(terms: readonly string[]): Promise<GlossaryEntry[]> {
  const doc = await requireDoc("01-conventions");
  const start = doc.tree.children.findIndex((n) => n.type === "heading" && plainText(n.children).startsWith("1. Words"));
  const table = doc.tree.children.slice(start + 1).find((n): n is Table => n.type === "table");
  if (start < 0 || !table) throw new Error("01-conventions: no glossary table under §1 Words");
  const rows = new Map(
    table.children.slice(1).map((row) => {
      const [termCell, meaningCell] = row.children;
      return [plainText(termCell?.children ?? []).trim(), meaningCell] as const;
    }),
  );
  return terms.map((term) => {
    const cell = rows.get(term);
    if (!cell) throw new Error(`01-conventions §1: no entry for "${term}"`);
    return { term, meaning: { type: "paragraph", children: cell.children } };
  });
}
