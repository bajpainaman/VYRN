import { describe, expect, it } from "vitest";
import { metadata } from "./page";

describe("homepage metadata", () => {
  it("declares the homepage as its own canonical URL", () => {
    expect(metadata.alternates?.canonical).toBe("/");
  });
});
