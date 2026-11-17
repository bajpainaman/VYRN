import { describe, expect, it } from "vitest";
import { rank, type SearchEntry } from "./SpecSearch";

const entry = (text: string, kind: SearchEntry["kind"] = "section"): SearchEntry => ({ text, href: `/docs/x#${text}`, where: "05 Engine", kind });
const entries = [entry("8.3 Step cut"), entry("3.3 Step cuts"), entry("7.1 Cut core loop"), entry("INV-WRITER", "id"), entry("2.1 State")];

describe("rank", () => {
  it("returns nothing for an empty query", () => {
    expect(rank(entries, "   ")).toEqual([]);
  });

  it("requires every word, case-insensitively", () => {
    expect(rank(entries, "STEP cut").map((e) => e.text)).toEqual(["8.3 Step cut", "3.3 Step cuts"]);
  });

  it("puts an exact match first", () => {
    expect(rank(entries, "inv-writer")[0]?.text).toBe("INV-WRITER");
  });

  it("prefers matches at the start, then shorter text", () => {
    expect(rank([entry("the cut core"), entry("cut core loop"), entry("cut")], "cut").map((e) => e.text)).toEqual([
      "cut",
      "cut core loop",
      "the cut core",
    ]);
  });

  it("caps the list at ten results", () => {
    const many = Array.from({ length: 25 }, (_, i) => entry(`lane ${i}`));
    expect(rank(many, "lane")).toHaveLength(10);
  });
});
