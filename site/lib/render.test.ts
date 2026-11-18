import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { renderNodes } from "./render";
import { getSectionIndex, parseMarkdown } from "./spec";

const render = (markdown: string, slug: string) => renderNodes(parseMarkdown(markdown), slug);

/** The master diagram's ASCII, which figure 00-index-00 redraws. */
const master: string = JSON.parse(readFileSync(path.join("diagrams", "inventory.json"), "utf8"))["00-index"][0].ascii;

describe("renderNodes: § references", () => {
  it("links a bare § to the section in the same chapter", async () => {
    const id = (await getSectionIndex())["05-engine"]?.["6.8"];
    expect(id).toBeTruthy();
    const { html } = await render("Shed before it is accepted (§6.8).", "05-engine");
    expect(html).toContain(`<a href="#${id}" class="spec-ref">§6.8</a>`);
  });

  it("links a chapter-prefixed § to the other chapter", async () => {
    const id = (await getSectionIndex())["01-conventions"]?.["14.0"];
    const { html } = await render("index 0–9 (01 §14.0).", "05-engine");
    expect(html).toContain(`href="/docs/01-conventions#${id}"`);
  });

  it("reads the chapter from an inline code span just before the §", async () => {
    const id = (await getSectionIndex())["design"]?.["3"];
    const { html } = await render("Source: `DESIGN.md` §3.", "05-engine");
    expect(html).toContain(`href="/docs/design#${id}"`);
  });

  it("leaves a § it cannot resolve as plain text", async () => {
    const { html } = await render("See §99.9.", "05-engine");
    expect(html).not.toContain("spec-ref");
  });
});

describe("renderNodes: IDs, headings, tables", () => {
  it("links a global spec ID to the chapter that defines it", async () => {
    const { html } = await render("Each field has one writer (`INV-WRITER`).", "05-engine");
    expect(html).toContain('href="/docs/01-conventions#id-INV-WRITER"');
  });

  it("gives headings a copyable anchor and lists them in the TOC without it", async () => {
    const { html, toc } = await render("## 2. The schedule\n\ntext", "08-epochs");
    expect(html).toContain('<a href="#2-the-schedule" class="heading-anchor"');
    expect(toc).toEqual([{ depth: 2, text: "2. The schedule", id: "2-the-schedule" }]);
  });

  it("wraps tables in a scroll region and anchors ID rows", async () => {
    const { html } = await render("| ID | Rule |\n|---|---|\n| C-NOCHIP | no FPGA |", "00-index");
    expect(html).toContain('<div class="table-wrap" tabindex="0" role="region" aria-label="Table">');
    expect(html).toContain('<tr id="id-C-NOCHIP" class="id-row">');
  });
});

describe("renderNodes: diagrams", () => {
  it("places the drawn figure over its ASCII original, keyed by the block's text", async () => {
    const { html } = await render("```\n" + master + "\n```", "00-index");
    expect(html).toContain('src="/diagrams/00-index-00.svg"');
    expect(html).toContain('src="/diagrams/00-index-00-dark.svg"');
    expect(html).toContain('<details class="diagram-ascii">');
    expect(html).toContain('<pre class="ascii">');
  });

  it("keeps the figure on its block when another diagram comes first, and drops it when the text changes", async () => {
    const moved = await render("```\n┌──┐\n└──┘\n```\n\n```\n" + master + "\n```", "00-index");
    expect(moved.html.match(/<figure/g)).toHaveLength(1);
    // The figure wraps the second block, the master diagram; the box before it stays plain.
    expect(moved.html.indexOf("<figure")).toBeGreaterThan(moved.html.indexOf("┌──┐"));
    const edited = await render("```\n" + master + " │\n```", "00-index");
    expect(edited.html).not.toContain("<figure");
  });

  it("leaves an ASCII block with no drawing as a plain diagram and code as code", async () => {
    const { html } = await render("```\n┌──┐\n└──┘\n```\n\n```rust\nfn f() {}\n```", "01-conventions");
    expect(html).not.toContain("<figure");
    expect(html).toContain('class="ascii-wrap"');
    expect(html).toContain('<div class="code-wrap"');
  });
});
