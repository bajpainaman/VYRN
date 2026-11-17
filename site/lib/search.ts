import "server-only";
import GithubSlugger from "github-slugger";
import { cacheLife } from "next/cache";
import type { RootContent as MdNode } from "mdast";
import { getDocs, getIdIndex, plainText } from "./spec";

/** One searchable target: a section heading or a spec ID, with the page and anchor it lives at. */
export type SearchEntry = {
  /** What the reader types against: "6.8 Shedding before acceptance", "INV-WRITER". */
  text: string;
  href: string;
  /** Where it lives, shown beside the result: "05 Engine", "DESIGN". */
  where: string;
  kind: "section" | "id";
};

export async function getSearchIndex(): Promise<SearchEntry[]> {
  "use cache";
  cacheLife("max");
  const docs = await getDocs();
  const where = new Map(docs.map((d) => [d.slug, d.number === "D" ? "DESIGN" : `${d.number} ${d.short}`]));
  const entries: SearchEntry[] = [];

  for (const doc of docs) {
    // Same slugger, same order as rehype-slug, so every href lands on a real id.
    const slugger = new GithubSlugger();
    const walk = (nodes: readonly MdNode[]) => {
      for (const node of nodes) {
        if (node.type === "heading") {
          const text = plainText(node.children);
          const id = slugger.slug(text);
          if (node.depth >= 2 && node.depth <= 4) {
            entries.push({ text, href: `/docs/${doc.slug}#${id}`, where: where.get(doc.slug) ?? doc.slug, kind: "section" });
          }
        } else if ("children" in node) {
          walk(node.children as MdNode[]);
        }
      }
    };
    walk(doc.tree.children);
  }

  for (const [id, owner] of Object.entries(await getIdIndex())) {
    entries.push({ text: id, href: `/docs/${owner}#id-${id}`, where: where.get(owner) ?? owner, kind: "id" });
  }
  return entries;
}
