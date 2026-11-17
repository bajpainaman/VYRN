import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";
import { accepted, proxy, wantsMarkdown } from "./proxy";

const request = (path: string, accept: string) => new NextRequest(`https://www.vryn.trade${path}`, { headers: { accept } });

describe("Accept parsing", () => {
  it("orders types by quality and drops q=0", () => {
    expect(accepted("text/html;q=0.5, text/markdown, application/json;q=0")).toEqual(["text/markdown", "text/html"]);
  });

  it("prefers Markdown only when it ranks above HTML", () => {
    expect(wantsMarkdown(accepted("text/markdown"))).toBe(true);
    expect(wantsMarkdown(accepted("text/html, text/markdown;q=0.9"))).toBe(false);
    expect(wantsMarkdown(accepted("*/*"))).toBe(false);
  });
});

describe("proxy", () => {
  it("routes Markdown requests for the homepage and chapters to the Markdown handlers", () => {
    expect(proxy(request("/", "text/markdown")).headers.get("x-middleware-rewrite")).toBe("https://www.vryn.trade/md");
    expect(proxy(request("/docs/05-engine.md", "*/*")).headers.get("x-middleware-rewrite")).toBe("https://www.vryn.trade/md/docs/05-engine");
  });

  it("answers an unknown path with a Markdown 404 that links llms.txt", async () => {
    const res = proxy(request("/__probe-404", "text/markdown"));
    expect(res.status).toBe(404);
    expect(res.headers.get("content-type")).toBe("text/markdown; charset=utf-8");
    const body = await res.text();
    expect(body.length).toBeGreaterThan(20);
    expect(body).toContain("https://www.vryn.trade/llms.txt");
  });

  it("answers an unknown path with a JSON 404 for JSON clients, and leaves HTML to Next", async () => {
    const json = proxy(request("/__probe-404", "application/json"));
    expect(json.status).toBe(404);
    expect((await json.json()).error.code).toBe("not_found");
    expect(proxy(request("/__probe-404", "text/html")).status).toBe(200);
  });

  it("leaves served paths and chapter share images alone", () => {
    for (const path of ["/about", "/api/v1/chapters", "/llms.txt", "/docs/05-engine/opengraph-image"]) {
      expect(proxy(request(path, "text/markdown")).headers.get("x-middleware-rewrite"), path).toBeNull();
    }
  });
});
