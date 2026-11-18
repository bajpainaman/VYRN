import "server-only";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { cacheLife } from "next/cache";

/**
 * Drawn versions of spec ASCII diagrams. The spec requires every diagram in ASCII; these figures are
 * shown in addition, never instead. Each is keyed to the ASCII block it redraws by document and by
 * a hash of the block's text ([`asciiHash`], the `hash` scripts/diagram-inventory.mjs lists), so a
 * block that moves keeps its figure, and a block whose text changes loses it until someone checks
 * the drawing still matches and updates the hash.
 * Sources live in `diagrams/*.excalidraw`, exports in `public/diagrams/*.svg`, and each drawing
 * worker's entries in `diagrams/manifest/*.json`.
 */
export type Figure = {
  slug: string;
  /** [`asciiHash`] of the ASCII block this figure redraws. */
  ascii: string;
  /** File stem shared by the .excalidraw source and the .svg export. */
  file: string;
  width: number;
  height: number;
  alt: string;
};

const MANIFEST_DIR = path.join(process.cwd(), "diagrams", "manifest");

function isFigure(value: unknown): value is Figure {
  if (typeof value !== "object" || value === null) return false;
  const f = value as Record<string, unknown>;
  return (
    typeof f.slug === "string" &&
    typeof f.ascii === "string" &&
    typeof f.file === "string" &&
    typeof f.width === "number" &&
    typeof f.height === "number" &&
    typeof f.alt === "string"
  );
}

export async function getFigures(): Promise<Figure[]> {
  "use cache";
  cacheLife("max");
  let names: string[];
  try {
    names = (await readdir(MANIFEST_DIR)).filter((n) => n.endsWith(".json")).sort();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  const figures: Figure[] = [];
  for (const name of names) {
    const raw: unknown = JSON.parse(await readFile(path.join(MANIFEST_DIR, name), "utf8"));
    if (!Array.isArray(raw)) throw new Error(`diagrams/manifest/${name}: expected an array`);
    raw.forEach((entry, i) => {
      if (!isFigure(entry)) throw new Error(`diagrams/manifest/${name}[${i}]: malformed figure entry`);
      figures.push(entry);
    });
  }
  return figures;
}

/** The first 12 hex digits of the SHA-256 of an ASCII block's text, trailing whitespace trimmed. */
export function asciiHash(text: string): string {
  return createHash("sha256").update(text.trimEnd()).digest("hex").slice(0, 12);
}

export function figureKey(slug: string, ascii: string): string {
  return `${slug}#${ascii}`;
}
