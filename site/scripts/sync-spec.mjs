// Copies DESIGN.md and spec/*.md from the spec repo into content/.
// The site builds remotely on Vercel, where the spec repo is not present, so the
// copy is committed with the site. Run before each deploy: `pnpm sync-spec`.
// SPEC_SOURCE points at the spec root (default: the parent folder).
import { cp, mkdir, readdir, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = path.resolve(siteRoot, process.env.SPEC_SOURCE ?? "..");
const target = path.join(siteRoot, "content");

async function requireFile(file) {
  try {
    const info = await stat(file);
    if (!info.isFile()) throw new Error("not a file");
  } catch (error) {
    throw new Error(`sync-spec: expected ${file} (SPEC_SOURCE=${source}): ${error.message}`);
  }
}

const designPath = path.join(source, "DESIGN.md");
const specDir = path.join(source, "spec");
await requireFile(designPath);

const chapters = (await readdir(specDir)).filter((name) => /^\d{2}-.+\.md$/.test(name)).sort();
if (chapters.length === 0) throw new Error(`sync-spec: no chapters found in ${specDir}`);

await rm(target, { recursive: true, force: true });
await mkdir(path.join(target, "spec"), { recursive: true });
await cp(designPath, path.join(target, "DESIGN.md"));
await Promise.all(
  chapters.map((name) => cp(path.join(specDir, name), path.join(target, "spec", name))),
);

// The proxy answers unknown /docs/<slug> with a real 404; it reads the known slugs from this list.
const slugs = ["design", ...chapters.map((name) => name.replace(/\.md$/, ""))];
await writeFile(path.join(siteRoot, "lib", "doc-slugs.json"), `${JSON.stringify(slugs, null, 2)}\n`);

console.log(`sync-spec: copied DESIGN.md and ${chapters.length} chapters from ${source}`);
