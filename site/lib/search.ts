import "server-only";
import GithubSlugger from "github-slugger";
import { cacheLife } from "next/cache";
import type { RootContent as MdNode } from "mdast";
import { getDocs, getIdIndex, plainText } from "./spec";

import type { SearchEntry } from "./search-rank";

export type { SearchEntry };

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
