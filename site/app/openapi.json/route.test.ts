import { describe, expect, it } from "vitest";
import { GET } from "./route";

describe("GET /openapi.json", () => {
  it("is OpenAPI 3.1 with every endpoint, a shared error schema, and the versioning policy", async () => {
    const spec = await (await GET()).json();
    expect(spec.openapi).toBe("3.1.0");
    expect(Object.keys(spec.paths)).toEqual(["/api/v1/chapters", "/api/v1/chapters/{slug}", "/api/v1/search", "/api/v1/ids/{id}"]);
    expect(spec.components.schemas.Error.properties.error.required).toEqual(["code", "message", "hint"]);
    expect(spec.info.description).toContain("Sunset (RFC 8594)");
    expect(spec.externalDocs.url).toBe("https://www.vryn.trade/developers");
  });
});
