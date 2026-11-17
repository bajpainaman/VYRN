import { describe, expect, it } from "vitest";
import {
  apiError,
  chapterMarkdown,
  getChapterDetail,
  getChapterSummaries,
  landingMarkdown,
  llmsFullTxt,
  llmsTxt,
  MARKDOWN_HEADERS,
  SITE_ORIGIN,
} from "./agent";
import { getSectionIndex } from "./spec";

describe("chapter summaries and details", () => {
  it("lists DESIGN.md and chapters 00–11 with canonical HTML and Markdown URLs", async () => {
    const chapters = await getChapterSummaries();
    expect(chapters.map((c) => c.slug)).toEqual([
      "design", "00-index", "01-conventions", "02-requirements", "03-architecture", "04-protocol",
      "05-engine", "06-platform", "07-replication", "08-epochs", "09-chain", "10-accounts-risk-md", "11-build",
    ]);
    const engine = chapters.find((c) => c.slug === "05-engine")!;
    expect(engine).toMatchObject({ number: "05", url: `${SITE_ORIGIN}/docs/05-engine`, markdown_url: `${SITE_ORIGIN}/docs/05-engine.md` });
    expect(engine.title).not.toMatch(/^\d{2}\./);
  });

  it("gives every numbered section an anchor the rendered page carries", async () => {
    const detail = await getChapterDetail("08-epochs");
    const ids = new Set(Object.values((await getSectionIndex())["08-epochs"] ?? {}));
    expect(detail?.sections.length).toBeGreaterThan(10);
    for (const s of detail!.sections) expect(ids.has(s.url.split("#")[1]!), s.number).toBe(true);
  });

  it("returns undefined for an unknown chapter", async () => {
    expect(await getChapterDetail("99-nope")).toBeUndefined();
    expect(await chapterMarkdown("99-nope")).toBeUndefined();
  });

  it("serves a chapter's Markdown under a header that names its source", async () => {
    const md = await chapterMarkdown("05-engine");
    expect(md).toMatch(/^<!-- 05: .+ · Draft 0\.2, 2026-11-13 · HTML: https:\/\/www\.vryn\.trade\/docs\/05-engine -->/);
  });
});

describe("landing Markdown and llms.txt", () => {
  it("leads with the six lines from DESIGN.md §0 and the corrected lane count", async () => {
    const md = await landingMarkdown();
    expect(md.startsWith("# VYRN")).toBe(true);
    expect(md).toContain("## The answer in six lines (DESIGN.md §0)");
    expect(md).toContain("49 lane");
    expect(md).not.toContain("50 lane");
    expect(md).toContain(`${SITE_ORIGIN}/openapi.json`);
  });

  it("tells agents when to use the site, and that there is no trading API", async () => {
    const txt = await llmsTxt();
    expect(txt).toMatch(/^# VYRN\n\n> /);
    expect(txt).toContain("## When to use");
    expect(txt).toContain("## How to call");
    expect(txt).toContain(`${SITE_ORIGIN}/developers`);
    expect(txt).toContain("there is no trading API");
    expect(txt).toContain(`${SITE_ORIGIN}/docs/11-build.md`);
  });

  it("puts every document in llms-full.txt", async () => {
    const full = await llmsFullTxt();
    for (const c of await getChapterSummaries()) expect(full).toContain(`<!-- ${SITE_ORIGIN}/docs/${c.slug} -->`);
  });
});

describe("apiError", () => {
  it("returns the shared error shape with the status, a hint and the docs link", async () => {
    const res = apiError(404, "not_found", "No chapter \"x\".", "Use one of: design.");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({
      error: { code: "not_found", message: "No chapter \"x\".", hint: "Use one of: design.", docs: `${SITE_ORIGIN}/openapi.json` },
    });
  });

  it("marks Markdown responses as varying by Accept", () => {
    expect(MARKDOWN_HEADERS).toEqual({ "Content-Type": "text/markdown; charset=utf-8", Vary: "Accept" });
  });
});
