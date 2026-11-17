import { describe, expect, it } from "vitest";
import { renderNodes } from "./render";
import { getSearchIndex } from "./search";
import { getDoc } from "./spec";

describe("getSearchIndex", () => {
  it("covers sections and IDs, and every href in a chapter lands on an id the page renders", async () => {
    const entries = await getSearchIndex();
    expect(entries.length).toBeGreaterThan(800);
    expect(entries.some((e) => e.kind === "id" && e.text === "INV-WRITER")).toBe(true);

    for (const slug of ["design", "08-epochs"]) {
      const doc = await getDoc(slug);
      if (!doc) throw new Error(`missing ${slug}`);
      const { html } = await renderNodes(doc.tree, slug);
      const targets = entries.filter((e) => e.href.startsWith(`/docs/${slug}#`));
      expect(targets.length).toBeGreaterThan(10);
      for (const e of targets) {
        const id = e.href.split("#")[1]!;
        expect(html, `${e.text} → ${id}`).toContain(`id="${id}"`);
      }
    }
  });
});
