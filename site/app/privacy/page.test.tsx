import { describe, expect, it } from "vitest";
import Page, { metadata } from "./page";

describe("/privacy", () => {
  it("has a title, a description and its own canonical URL", () => {
    expect(metadata.title).toBeTruthy();
    expect(String(metadata.description).length).toBeGreaterThan(20);
    expect(metadata.alternates?.canonical).toBe("/privacy");
  });

  it("renders a page component", () => {
    expect(typeof Page).toBe("function");
  });
});
