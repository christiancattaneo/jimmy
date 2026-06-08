/**
 * Minimal Anthropic client for jimmy's optional AI layer. No SDK dependency:
 * a single fetch against the Messages API. The API key is read from the
 * environment or a local .env / .env.local (never committed). AI is strictly
 * opt-in (--ai) and only ever PROPOSES remediation; it never decides a verdict,
 * so jimmy stays deterministic.
 *
 * Cost control (paid service):
 *   Model: claude-opus-4-8 at $5 / $25 per million input / output tokens.
 *   Each remediation call is capped at MAX_OUTPUT_TOKENS output and is sent at
 *   most one batched request per run. With a ~4k-token input and 1.5k output,
 *   worst case is about 4000/1e6*$5 + 1500/1e6*$25 = $0.02 + $0.0375 ≈ $0.06
 *   per run. jimmy makes at most ONE call per --ai invocation, so the maximum
 *   spend per command is ~$0.06. No retries, no loops.
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const DEFAULT_MODEL = "claude-opus-4-8";
const MAX_OUTPUT_TOKENS = 1500;
const API_URL = "https://api.anthropic.com/v1/messages";

/** Read a key from process.env or a local .env/.env.local (first match wins). */
export function resolveApiKey(cwd = process.cwd()): string | undefined {
  if (process.env.ANTHROPIC_API_KEY) return process.env.ANTHROPIC_API_KEY;
  for (const name of [".env.local", ".env"]) {
    const path = resolve(cwd, name);
    if (!existsSync(path)) continue;
    const m = readFileSync(path, "utf-8").match(/^\s*ANTHROPIC_API_KEY\s*=\s*(.+?)\s*$/m);
    if (m) return m[1]!.replace(/^["']|["']$/g, "");
  }
  return undefined;
}

export interface AiResult {
  text: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  /** Estimated USD cost of this call. */
  costUsd: number;
}

/** One bounded, non-streaming Messages call. Throws on missing key or API error. */
export async function askClaude(prompt: string, opts: { apiKey?: string; model?: string } = {}): Promise<AiResult> {
  const apiKey = opts.apiKey ?? resolveApiKey();
  if (!apiKey) {
    throw new Error("No ANTHROPIC_API_KEY found (env or .env.local). AI features need it.");
  }
  const model = opts.model ?? process.env.JIMMY_AI_MODEL ?? DEFAULT_MODEL;

  const res = await fetch(API_URL, {
    method: "POST",
    headers: {
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model,
      max_tokens: MAX_OUTPUT_TOKENS,
      messages: [{ role: "user", content: prompt }],
    }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Anthropic API error ${res.status}: ${body.slice(0, 300)}`);
  }
  const data = (await res.json()) as {
    content: { type: string; text?: string }[];
    usage?: { input_tokens: number; output_tokens: number };
    model: string;
  };
  const text = data.content.filter((c) => c.type === "text").map((c) => c.text ?? "").join("");
  const inputTokens = data.usage?.input_tokens ?? 0;
  const outputTokens = data.usage?.output_tokens ?? 0;
  // Opus 4.8 pricing: $5 / $25 per million input / output tokens.
  const costUsd = (inputTokens / 1e6) * 5 + (outputTokens / 1e6) * 25;
  return { text, model: data.model ?? model, inputTokens, outputTokens, costUsd };
}
