import path from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname),
      "server-only": path.resolve(import.meta.dirname, "test/server-only.ts"),
      "next/cache": path.resolve(import.meta.dirname, "test/next-cache.ts"),
    },
  },
  // The first test parses the whole 1.4 MB spec; later tests reuse the cached result.
  test: { environment: "node", testTimeout: 60_000, include: ["**/*.test.ts", "**/*.test.tsx"], exclude: ["node_modules/**", ".next/**"] },
});
