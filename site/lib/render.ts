import "server-only";
import type { Element, ElementContent, Root as HastRoot, Text } from "hast";
import type { Root as MdRoot, RootContent as MdNode } from "mdast";
import { toHtml } from "hast-util-to-html";
import { toString as hastText } from "hast-util-to-string";
import rehypeSlug from "rehype-slug";
import remarkRehype from "remark-rehype";
import { unified } from "unified";
import { visitParents, SKIP } from "unist-util-visit-parents";
import { figureKey, getFigures, type Figure } from "./diagrams";
import {
  getChapterSlugs,
  getIdIndex,
  getSectionIndex,
  resolveSpecHref,
  rowId,
  type SectionIndex,
  type TocEntry,
} from "./spec";

type RenderContext = {
  slug: string;
  idIndex: ReadonlyMap<string, string>;
  sections: SectionIndex;
  chapters: Readonly<Record<string, string>>;
  figures: ReadonlyMap<string, Figure>;
  /** Position of the first ASCII block of this fragment within its whole document. */
  asciiStart: number;
};

const NO_LINK_ANCESTORS = new Set(["a", "pre", "h1", "h2", "h3", "h4", "h5", "h6"]);
const HEADINGS = new Set(["h2", "h3", "h4"]);

// "§6.8", "01 §14.0", "DESIGN §3". The chapter, when present, is the two digits or DESIGN just before.
const SECTION_REF = /(?:\b(DESIGN|\d{2})\s+)?§\s?(\d+(?:\.\d+)*)/g;

const el = (tagName: string, properties: Element["properties"], children: ElementContent[] = []): Element => ({
  type: "element",
  tagName,
  properties,
  children,
});
const txt = (value: string): Text => ({ type: "text", value });

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function idHref(id: string, owner: string, ctx: RenderContext): string {
  return owner === ctx.slug ? `#id-${id}` : `/docs/${owner}#id-${id}`;
}

/** The chapter a code span names: "01", "05-engine.md", "DESIGN.md". */
function chapterOf(code: string): string | undefined {
  if (/^DESIGN(\.md)?$/.test(code)) return "DESIGN";
  return /^(\d{2})(-[\w-]+)?(\.md)?$/.exec(code)?.[1];
}

function sectionHref(chapter: string | undefined, number: string, ctx: RenderContext): string | undefined {
  const slug = chapter ? ctx.chapters[chapter] : ctx.slug;
  const id = slug ? ctx.sections[slug]?.[number] : undefined;
  if (!slug || !id) return undefined;
  return slug === ctx.slug ? `#${id}` : `/docs/${slug}#${id}`;
}

const ARROW_SVG = el("svg", { width: 18, height: 14, viewBox: "0 0 18 14", ariaHidden: "true", focusable: "false", className: ["summary-arrow"] }, [
  el("path", { d: "M1 7h14M10 1.5 15.5 7 10 12.5", fill: "none", stroke: "currentColor", strokeWidth: "2.4", strokeLinecap: "square" }),
]);

function figureNode(figure: Figure, pre: Element): Element {
  const src = `/diagrams/${figure.file}.svg`;
  return el("figure", { className: ["diagram"] }, [
    el("div", { className: ["diagram-scroll"], tabIndex: 0, role: "region", ariaLabel: "Diagram" }, [
      // One drawing per theme; CSS hides the other, and a hidden lazy image is never fetched.
      el("img", { src, width: figure.width, height: figure.height, alt: figure.alt, loading: "lazy", decoding: "async", className: ["fig-light"], style: `--fig-w:${figure.width}` }),
      el("img", { src: `/diagrams/${figure.file}-dark.svg`, width: figure.width, height: figure.height, alt: figure.alt, loading: "lazy", decoding: "async", className: ["fig-dark"], style: `--fig-w:${figure.width}` }),
    ]),
    el("figcaption", {}, [
      txt("Drawn from the ASCII original below. "),
      el("a", { href: src, target: "_blank", rel: ["noopener"] }, [txt("Open full size")]),
      txt(" · "),
      el("a", { href: `/diagrams/${figure.file}.excalidraw`, download: true }, [txt("Download the Excalidraw file")]),
    ]),
    el("details", { className: ["diagram-ascii"] }, [
      el("summary", {}, [structuredClone(ARROW_SVG), txt("ASCII original")]),
      el("div", { className: ["ascii-wrap"], tabIndex: 0, role: "region", ariaLabel: "ASCII diagram" }, [pre]),
    ]),
  ]);
}

/**
 * Rewrites spec links, anchors ID rows and headings, wraps tables and code, places drawn figures over
 * their ASCII originals, and links every global spec ID and every § reference.
 */
function rehypeSpec(ctx: RenderContext) {
  const ids = [...ctx.idIndex.keys()].sort((a, b) => b.length - a.length);
  const idPattern = ids.length
    ? new RegExp(`(?<![A-Za-z0-9_-])(${ids.map(escapeRegExp).join("|")})(?![A-Za-z0-9_-])`, "g")
    : null;

  return (tree: HastRoot) => {
    const usedRowIds = new Set<string>();
    let asciiCount = ctx.asciiStart;

    visitParents(tree, "element", (node: Element, ancestors) => {
      const parent = ancestors.at(-1);
      if (!parent || !("children" in parent)) return;
      const siblings = parent.children as ElementContent[];

      if (node.tagName === "a" && typeof node.properties.href === "string") {
        node.properties.href = resolveSpecHref(node.properties.href);
        return;
      }
      if (HEADINGS.has(node.tagName) && typeof node.properties.id === "string") {
        node.children.push(
          el("a", { href: `#${node.properties.id}`, className: ["heading-anchor"], ariaLabel: `Link to this section: ${hastText(node)}` }, [txt("#")]),
        );
        return SKIP;
      }
      if (node.tagName === "tr" && parent.type === "element" && parent.tagName === "tbody") {
        const first = node.children.find((c): c is Element => c.type === "element");
        const id = first ? rowId(hastText(first)) : undefined;
        if (id && !usedRowIds.has(id)) {
          usedRowIds.add(id);
          node.properties.id = `id-${id}`;
          node.properties.className = ["id-row"];
        }
        return;
      }
      if (node.tagName === "table") {
        const wrap = el("div", { className: ["table-wrap"], tabIndex: 0, role: "region", ariaLabel: "Table" }, [node]);
        siblings[siblings.indexOf(node)] = wrap;
        return; // keep walking into the cells: they carry most of the spec IDs
      }
      if (node.tagName === "pre") {
        const code = node.children.find((c): c is Element => c.type === "element" && c.tagName === "code");
        const classes = (code?.properties.className as string[] | undefined) ?? [];
        const lang = classes.find((c) => c.startsWith("language-"))?.slice("language-".length);
        const at = siblings.indexOf(node);
        if (lang && lang !== "text") {
          node.properties.className = ["code"];
          node.properties.dataLang = lang;
          siblings[at] = el("div", { className: ["code-wrap"], tabIndex: 0, role: "region", ariaLabel: "Code" }, [node]);
          return SKIP;
        }
        node.properties.className = ["ascii"];
        const figure = ctx.figures.get(figureKey(ctx.slug, asciiCount++));
        siblings[at] = figure
          ? figureNode(figure, node)
          : el("div", { className: ["ascii-wrap"], tabIndex: 0, role: "region", ariaLabel: "Diagram" }, [node]);
        return SKIP;
      }
      if (node.tagName === "code" && parent.type === "element" && !NO_LINK_ANCESTORS.has(parent.tagName)) {
        const text = hastText(node);
        const owner = ctx.idIndex.get(text);
        if (owner) {
          siblings[siblings.indexOf(node)] = el("a", { href: idHref(text, owner, ctx), className: ["spec-id"] }, [{ ...node }]);
          return SKIP;
        }
      }
    });

    visitParents(tree, "text", (node: Text, ancestors) => {
      if (ancestors.some((a) => a.type === "element" && (NO_LINK_ANCESTORS.has(a.tagName) || a.tagName === "code"))) return;
      const parent = ancestors.at(-1);
      if (!parent || !("children" in parent)) return;
      const siblings = parent.children as ElementContent[];
      const at = siblings.indexOf(node);

      // "spec `01` §14.17", "`DESIGN.md` §3", "`05-engine.md` §6": the chapter sits in the inline code just before.
      const prev = siblings[at - 1];
      const prevChapter = prev?.type === "element" && prev.tagName === "code" ? chapterOf(hastText(prev)) : undefined;

      type Hit = { start: number; end: number; node: Element };
      const hits: Hit[] = [];
      for (const m of node.value.matchAll(SECTION_REF)) {
        const leading = node.value.slice(0, m.index).trim() === "" ? prevChapter : undefined;
        const href = sectionHref(m[1] ?? leading, m[2]!, ctx);
        if (href) hits.push({ start: m.index, end: m.index + m[0].length, node: el("a", { href, className: ["spec-ref"] }, [txt(m[0])]) });
      }
      if (idPattern) {
        for (const m of node.value.matchAll(idPattern)) {
          const id = m[1]!;
          if (hits.some((h) => m.index < h.end && m.index + id.length > h.start)) continue;
          hits.push({ start: m.index, end: m.index + id.length, node: el("a", { href: idHref(id, ctx.idIndex.get(id)!, ctx), className: ["spec-id"] }, [txt(id)]) });
        }
      }
      if (hits.length === 0) return;
      hits.sort((a, b) => a.start - b.start);

      const parts: ElementContent[] = [];
      let last = 0;
      for (const hit of hits) {
        if (hit.start > last) parts.push(txt(node.value.slice(last, hit.start)));
        parts.push(hit.node);
        last = hit.end;
      }
      if (last < node.value.length) parts.push(txt(node.value.slice(last)));
      siblings.splice(at, 1, ...parts);
      return [SKIP, at + parts.length];
    });
  };
}

function collectToc(tree: HastRoot): TocEntry[] {
  const toc: TocEntry[] = [];
  visitParents(tree, "element", (node: Element) => {
    if ((node.tagName === "h2" || node.tagName === "h3") && typeof node.properties.id === "string") {
      const text = hastText(node).replace(/#$/, "");
      toc.push({ depth: node.tagName === "h2" ? 2 : 3, text, id: node.properties.id });
      return SKIP;
    }
  });
  return toc;
}

export type Rendered = { html: string; toc: TocEntry[] };

/**
 * Renders spec Markdown to an HTML string. A string, not a React tree: the chapters run to 3,000
 * lines, and a string travels once in the page payload where an element tree costs several times more.
 */
export async function renderNodes(
  nodes: MdRoot | MdNode[],
  slug: string,
  options: { asciiStart?: number } = {},
): Promise<Rendered> {
  const root: MdRoot = Array.isArray(nodes) ? { type: "root", children: nodes } : nodes;
  const [idIndex, sections, chapters, figures] = await Promise.all([getIdIndex(), getSectionIndex(), getChapterSlugs(), getFigures()]);
  const ctx: RenderContext = {
    slug,
    idIndex: new Map(Object.entries(idIndex)),
    sections,
    chapters,
    figures: new Map(figures.map((f) => [figureKey(f.slug, f.asciiIndex), f])),
    asciiStart: options.asciiStart ?? 0,
  };
  const processor = unified().use(remarkRehype).use(rehypeSlug).use(rehypeSpec, ctx);
  const hast = (await processor.run(structuredClone(root))) as HastRoot;
  const toc = collectToc(hast);
  return { html: toHtml(hast), toc };
}
