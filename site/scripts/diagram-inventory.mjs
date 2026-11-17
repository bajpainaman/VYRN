// Lists every ASCII block per document with the same rule the renderer uses (fenced code with no
// language, or "text"), so a figure's asciiIndex always points at the block it redraws.
import { readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import remarkParse from "remark-parse";
import remarkGfm from "remark-gfm";
import { unified } from "unified";
import { visit } from "unist-util-visit";

const root = path.resolve(import.meta.dirname, "..");
const files = [["design", "content/DESIGN.md"]];
for (const name of (await readdir(path.join(root, "content/spec"))).sort()) {
  if (/^\d{2}-.+\.md$/.test(name)) files.push([name.replace(/\.md$/, ""), `content/spec/${name}`]);
}
const DIAGRAM = /[┌└│►▼▲◄═║]|─►|──/;
const out = {};
for (const [slug, file] of files) {
  const tree = unified().use(remarkParse).use(remarkGfm).parse(await readFile(path.join(root, file), "utf8"));
  let index = 0;
  const blocks = [];
  let heading = "";
  visit(tree, (node) => {
    if (node.type === "heading") heading = node.children.map((c) => c.value ?? "").join("");
    if (node.type !== "code" || (node.lang && node.lang !== "text")) return;
    if (DIAGRAM.test(node.value)) blocks.push({ asciiIndex: index, heading, line: node.position.start.line, ascii: node.value });
    index++;
  });
  out[slug] = blocks;
}
await writeFile(path.join(root, "diagrams/inventory.json"), JSON.stringify(out, null, 1));
console.log(Object.entries(out).map(([s, b]) => `${s}:${b.length}`).join(" "));
