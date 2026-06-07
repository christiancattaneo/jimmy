/**
 * Filesystem helpers for the migration linter. Kept separate from lint.ts so
 * the core linter (lintSqlText) stays free of node built-ins and bundles for
 * the browser playground.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { lintSqlText } from "./lint.js";
import type { Finding } from "../../report/findings.js";

export function lintFile(filePath: string): Finding[] {
  const text = readFileSync(filePath, "utf-8");
  return lintSqlText(text, filePath);
}

export function lintDirectory(dirPath: string): Finding[] {
  const files: string[] = [];
  walk(dirPath, files);
  const all: Finding[] = [];
  for (const f of files) {
    if (!f.endsWith(".sql")) continue;
    all.push(...lintFile(f));
  }
  return all;
}

function walk(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      walk(full, out);
    } else if (st.isFile()) {
      out.push(full);
    }
  }
}
