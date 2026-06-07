import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: ["src/index.ts", "src/cli/index.ts"],
    format: ["esm"],
    dts: true,
    clean: true,
    sourcemap: true,
    target: "node20",
    outDir: "dist",
    splitting: false,
    treeshake: true,
  },
  {
    // Browser bundle for the site playground: the migration linter only.
    entry: { "jimmy-lint": "src/browser.ts" },
    format: ["esm"],
    platform: "browser",
    target: "es2022",
    outDir: "site",
    minify: true,
    sourcemap: false,
    dts: false,
    clean: false,
  },
]);
