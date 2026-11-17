// Serves every diagram's Excalidraw source next to its SVG export, so a reader can download it, and
// writes each export's dark-theme copy (`<name>-dark.svg`, not committed) by swapping its palette.
import { copyFile, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const from = path.join(root, "diagrams");
const to = path.join(root, "public", "diagrams");
await mkdir(to, { recursive: true });
const sources = (await readdir(from)).filter((name) => name.endsWith(".excalidraw"));
await Promise.all(sources.map((name) => copyFile(path.join(from, name), path.join(to, name))));
console.log(`sync-diagrams: ${sources.length} Excalidraw sources published`);

// The diagram palette (DESIGN.md, Diagram style) on the dark sheet. Ink inverts, so an inked box turns
// pale and its code text dark; canary and pink fills stay their hue, dark enough for pale ink at 7:1+.
const DARK = {
  "#191b26": "#ebe6d2", // ink
  "#565a6b": "#b8bccb", // muted ink
  "#5a2d91": "#c4a6f7", // violet
  "#f2d447": "#534509", // canary fill
  "#f4b7c2": "#5a2836", // pink fill
  "#ede5f6": "#2e2542", // stamp wash
  "#ffffff": "#1c1d24", // white fill (clients, externals)
  "#eceaf2": "#121318", // code text inside an inked box
};
const FIGURE_DARK = "#121318"; // the canvas: --color-figure in the dark

function darkSvg(svg, name) {
  const swapped = svg.replace(/(fill|stroke)="(#[0-9a-f]{6})"/gi, (match, attr, hex) => {
    const dark = DARK[hex.toLowerCase()];
    if (!dark) throw new Error(`sync-diagrams: ${name} uses ${hex}, which has no dark-theme colour`);
    return `${attr}="${dark}"`;
  });
  // The canvas rect goes to the frame's own field, not the raised white-fill grey.
  return swapped.replace(/(<rect x="0" y="0" width="[\d.]+" height="[\d.]+" fill=")#1c1d24"/, `$1${FIGURE_DARK}"`);
}

const exports = (await readdir(to)).filter((name) => name.endsWith(".svg") && !name.endsWith("-dark.svg"));
await Promise.all(
  exports.map(async (name) => {
    const svg = await readFile(path.join(to, name), "utf8");
    await writeFile(path.join(to, name.replace(/\.svg$/, "-dark.svg")), darkSvg(svg, name));
  }),
);
console.log(`sync-diagrams: ${exports.length} dark-theme drawings written`);
