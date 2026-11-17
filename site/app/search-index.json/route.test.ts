import { describe, expect, it } from "vitest";
import { GET } from "./route";

describe("GET /search-index.json", () => {
  it("serves the index as JSON, every entry pointing into the docs", async () => {
    const response = await GET();
    expect(response.headers.get("content-type")).toContain("application/json");
    const entries = (await response.json()) as { href: string; kind: string }[];
    expect(entries.length).toBeGreaterThan(800);
    expect(entries.every((e) => e.href.startsWith("/docs/"))).toBe(true);
  });
});
