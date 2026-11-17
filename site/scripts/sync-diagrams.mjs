// Serves every diagram's Excalidraw source next to its SVG export, so a reader can download it.
import { copyFile, mkdir, readdir } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const from = path.join(root, "diagrams");
const to = path.join(root, "public", "diagrams");
await mkdir(to, { recursive: true });
const sources = (await readdir(from)).filter((name) => name.endsWith(".excalidraw"));
await Promise.all(sources.map((name) => copyFile(path.join(from, name), path.join(to, name))));
console.log(`sync-diagrams: ${sources.length} Excalidraw sources published`);
