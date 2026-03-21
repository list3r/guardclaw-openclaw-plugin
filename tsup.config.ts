import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    "index": "index.ts",
    "llm-detect-worker": "src/llm-detect-worker.ts",
  },
  format: ["esm"],
  target: "node22",
  platform: "node",
  outDir: "dist",
  splitting: true,
  clean: true,
  // openclaw/plugin-sdk is provided by the host — don't bundle it
  external: ["openclaw/plugin-sdk"],
  // Keep node: protocol imports external
  noExternal: [],
});
