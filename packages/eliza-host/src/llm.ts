/**
 * LLM failover for ElizaOS: Groq first, OpenRouter when Groq is rate-limited or failing.
 *
 * Both speak the OpenAI chat API. On a 429 the provider is skipped until its retry-after passes
 * (instead of waiting, the message goes straight to the next provider); on 5xx / timeout / network
 * errors it is skipped for 20 s. Registers TEXT_SMALL/LARGE and OBJECT_SMALL/LARGE with high priority,
 * so it wins over @elizaos/plugin-groq (which stays loaded for its tokenizer).
 */

export interface LlmProvider {
  name: string;
  baseUrl: string;
  apiKey: string;
  small: string;
  large: string;
  headers?: Record<string, string>;
  /** OpenRouter only: more models to try, in order, if the first is unavailable (sent as `models`). */
  fallbackModels?: string[];
}

export interface LlmStats { served: Record<string, number>; failovers: number; last?: string; cooling: Record<string, number> }

type Fetch = typeof fetch;
const sleepless = { now: () => Date.now() };

export class FailoverLlm {
  readonly stats: LlmStats = { served: {}, failovers: 0, cooling: {} };
  private cool = new Map<string, number>();
  readonly providers: LlmProvider[];
  private fetchImpl: Fetch;
  private timeoutMs: number;
  private clock: { now: () => number };
  constructor(providers: LlmProvider[], fetchImpl: Fetch = globalThis.fetch.bind(globalThis), timeoutMs = 45_000, clock = sleepless) {
    this.providers = providers; this.fetchImpl = fetchImpl; this.timeoutMs = timeoutMs; this.clock = clock;
  }

  private available() {
    const now = this.clock.now();
    const open = this.providers.filter((p) => (this.cool.get(p.name) || 0) <= now);
    return open.length ? open : [...this.providers].sort((a, b) => (this.cool.get(a.name) || 0) - (this.cool.get(b.name) || 0)).slice(0, 1);
  }

  private coolDown(p: LlmProvider, ms: number) {
    const until = this.clock.now() + Math.min(Math.max(ms, 1000), 60_000);
    this.cool.set(p.name, until);
    this.stats.cooling[p.name] = until;
  }

  async complete(size: "small" | "large", opts: { prompt: string; system?: string; temperature?: number; maxTokens?: number; stop?: string[]; json?: boolean }): Promise<string> {
    const errors: string[] = [];
    const order = this.available();
    for (let i = 0; i < order.length; i++) {
      const p = order[i];
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
      try {
        const res = await this.fetchImpl(`${p.baseUrl}/chat/completions`, {
          method: "POST",
          signal: ctrl.signal,
          headers: { "content-type": "application/json", authorization: `Bearer ${p.apiKey}`, ...(p.headers || {}) },
          body: JSON.stringify({
            model: size === "small" ? p.small : p.large,
            ...(p.fallbackModels?.length ? { models: [size === "small" ? p.small : p.large, ...p.fallbackModels].filter((m, i, a) => a.indexOf(m) === i).slice(0, 3) } : {}),
            messages: [...(opts.system ? [{ role: "system", content: opts.system }] : []), { role: "user", content: opts.prompt }],
            temperature: opts.temperature ?? 0.7,
            max_tokens: opts.maxTokens ?? 4096,
            ...(opts.stop?.length ? { stop: opts.stop.slice(0, 4) } : {}),
            ...(opts.json ? { response_format: { type: "json_object" } } : {}),
          }),
        });
        if (res.status === 429) {
          const ra = Number(res.headers.get("retry-after")) * 1000;
          const body = await res.text().catch(() => "");
          const hinted = Number(body.match(/try again in ([\d.]+)s/i)?.[1]) * 1000;
          this.coolDown(p, ra || hinted || 15_000);
          throw new Error(`${p.name} rate limited`);
        }
        if (!res.ok) { this.coolDown(p, res.status >= 500 ? 20_000 : 60_000); throw new Error(`${p.name} HTTP ${res.status}: ${(await res.text().catch(() => "")).slice(0, 160)}`); }
        const d: any = await res.json();
        const text = d?.choices?.[0]?.message?.content;
        if (typeof text !== "string" || !text.trim()) { this.coolDown(p, 20_000); throw new Error(`${p.name} returned no text`); }
        this.stats.served[p.name] = (this.stats.served[p.name] || 0) + 1;
        this.stats.last = p.name;
        if (i > 0) this.stats.failovers++;
        return text;
      } catch (err: any) {
        if (err?.name === "AbortError") { this.coolDown(p, 20_000); errors.push(`${p.name} timed out`); }
        else { if (!this.cool.has(p.name) || (this.cool.get(p.name) || 0) <= this.clock.now()) this.coolDown(p, 20_000); errors.push(err?.message || String(err)); }
      } finally {
        clearTimeout(timer);
      }
    }
    throw new Error(`All LLM providers failed: ${errors.join("; ")}`);
  }
}

/** Parse a JSON object out of a model reply (handles ```json fences and leading prose). */
export function parseJsonReply(text: string): unknown {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i)?.[1];
  const raw = (fenced ?? text).trim();
  try { return JSON.parse(raw); } catch {}
  const start = raw.indexOf("{"), end = raw.lastIndexOf("}");
  if (start >= 0 && end > start) return JSON.parse(raw.slice(start, end + 1));
  throw new Error("Model did not return JSON");
}

export function providersFromEnv(env: Record<string, string | undefined> = process.env): LlmProvider[] {
  const list: LlmProvider[] = [];
  if (env.GROQ_API_KEY) list.push({
    name: "groq", baseUrl: "https://api.groq.com/openai/v1", apiKey: env.GROQ_API_KEY,
    small: env.GROQ_SMALL_MODEL || "openai/gpt-oss-20b", large: env.GROQ_LARGE_MODEL || "openai/gpt-oss-120b",
  });
  if (env.OPENROUTER_API_KEY) {
    // OpenRouter: free models only (policy). Anything without ":free" is ignored, so a paid model can't be used by mistake.
    const free = (m?: string) => (m && m.trim().endsWith(":free") ? m.trim() : undefined);
    const DEFAULT = "nvidia/nemotron-3-super-120b-a12b:free";
    for (const [k, v] of Object.entries({ OPENROUTER_SMALL_MODEL: env.OPENROUTER_SMALL_MODEL, OPENROUTER_LARGE_MODEL: env.OPENROUTER_LARGE_MODEL }))
      if (v && !free(v)) console.warn(`[llm] ${k}=${v} ignored: OpenRouter is free-models-only. Using ${DEFAULT}.`);
    list.push({
      name: "openrouter", baseUrl: "https://openrouter.ai/api/v1", apiKey: env.OPENROUTER_API_KEY,
      small: free(env.OPENROUTER_SMALL_MODEL) || DEFAULT, large: free(env.OPENROUTER_LARGE_MODEL) || DEFAULT,
      fallbackModels: (env.OPENROUTER_FALLBACK_MODELS || "nvidia/nemotron-3-ultra-550b-a55b:free,google/gemma-4-31b-it:free").split(",").map((m) => free(m)).filter((m): m is string => !!m),
      headers: { "HTTP-Referer": "https://aiguardian.dev", "X-Title": "GuardianAI hosted Eliza" },
    });
  }
  return list;
}

/** ElizaOS model plugin backed by FailoverLlm. */
export function failoverPlugin(llm: FailoverLlm) {
  const text = (size: "small" | "large") => async (_rt: unknown, p: any) =>
    llm.complete(size, { prompt: p?.prompt ?? "", system: p?.system, temperature: p?.temperature, maxTokens: p?.maxTokens ?? p?.max_tokens, stop: p?.stopSequences });
  const object = (size: "small" | "large") => async (_rt: unknown, p: any) =>
    parseJsonReply(await llm.complete(size, { prompt: `${p?.prompt ?? ""}\n\nRespond with a single JSON object only.`, system: p?.system, temperature: p?.temperature ?? 0.2, json: true }));
  return {
    name: "guardianai-llm-failover",
    description: "Groq with OpenRouter failover",
    priority: 100,
    models: { TEXT_SMALL: text("small"), TEXT_LARGE: text("large"), OBJECT_SMALL: object("small"), OBJECT_LARGE: object("large") },
  };
}
