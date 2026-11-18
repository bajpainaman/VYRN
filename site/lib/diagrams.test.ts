import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { asciiHash, figureKey, getFigures } from "./diagrams";

describe("figureKey", () => {
  it("joins document and block hash", () => {
    expect(figureKey("03-architecture", "a9a4caaefa7f")).toBe("03-architecture#a9a4caaefa7f");
  });
});

describe("asciiHash", () => {
  it("is SHA-256's first 12 hex digits, trailing whitespace ignored", () => {
    // sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    expect(asciiHash("abc")).toBe("ba7816bf8f01");
    expect(asciiHash("abc\n  ")).toBe("ba7816bf8f01");
    expect(asciiHash(" abc")).not.toBe("ba7816bf8f01");
  });
});

describe("getFigures", () => {
  it("loads one figure per diagram, each keyed once, each with its SVG and source on disk", async () => {
    const figures = await getFigures();
    expect(figures).toHaveLength(89);
    const keys = new Set(figures.map((f) => figureKey(f.slug, f.ascii)));
    expect(keys.size).toBe(figures.length);
    for (const f of figures) {
      expect(existsSync(path.join("public", "diagrams", `${f.file}.svg`)), f.file).toBe(true);
      expect(existsSync(path.join("diagrams", `${f.file}.excalidraw`)), f.file).toBe(true);
      expect(f.width).toBeLessThanOrEqual(1200);
      expect(f.alt.length).toBeGreaterThan(40);
    }
  });

  it("points every figure at a diagram block the inventory lists, hashed as the renderer hashes it", async () => {
    const inventory: Record<string, { hash: string; ascii: string }[]> = JSON.parse(
      await readFile(path.join("diagrams", "inventory.json"), "utf8"),
    );
    for (const blocks of Object.values(inventory)) {
      for (const b of blocks) expect(asciiHash(b.ascii), b.hash).toBe(b.hash);
    }
    for (const f of await getFigures()) {
      const listed = (inventory[f.slug] ?? []).some((b) => b.hash === f.ascii);
      expect(listed, figureKey(f.slug, f.ascii)).toBe(true);
    }
  });
});
