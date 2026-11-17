import { existsSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { figureKey, getFigures } from "./diagrams";

describe("figureKey", () => {
  it("joins document and ASCII position", () => {
    expect(figureKey("03-architecture", 14)).toBe("03-architecture#14");
  });
});

describe("getFigures", () => {
  it("loads one figure per diagram, each keyed once, each with its SVG and source on disk", async () => {
    const figures = await getFigures();
    expect(figures).toHaveLength(89);
    const keys = new Set(figures.map((f) => figureKey(f.slug, f.asciiIndex)));
    expect(keys.size).toBe(figures.length);
    for (const f of figures) {
      expect(existsSync(path.join("public", "diagrams", `${f.file}.svg`)), f.file).toBe(true);
      expect(existsSync(path.join("diagrams", `${f.file}.excalidraw`)), f.file).toBe(true);
      expect(f.width).toBeLessThanOrEqual(1200);
      expect(f.alt.length).toBeGreaterThan(40);
    }
  });
});
