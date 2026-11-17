import { describe, expect, it } from "vitest";
import Page, { metadata } from "./page";

describe("/developers", () => {
  it("has a title, a description and its own canonical URL", () => {
    expect(metadata.title).toBeTruthy();
    expect(String(metadata.description).length).toBeGreaterThan(20);
    expect(metadata.alternates?.canonical).toBe("/developers");
  });

  it("renders a page component", () => {
    expect(typeof Page).toBe("function");
  });
});
