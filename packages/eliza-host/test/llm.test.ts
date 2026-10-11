// node test/llm.test.ts — failover logic, no network.
import { FailoverLlm, parseJsonReply, providersFromEnv } from "../src/llm.ts";
let pass = 0, fail = 0;
const ok = (c: boolean, l: string) => { c ? pass++ : fail++; console.log(`  [${c ? "+" : "-"}] ${l}`); };
const P = [
  { name: "groq", baseUrl: "https://g", apiKey: "g", small: "gs", large: "gl" },
  { name: "openrouter", baseUrl: "https://o", apiKey: "o", small: "os", large: "ol" },
];
const reply = (text: string) => new Response(JSON.stringify({ choices: [{ message: { content: text } }] }), { status: 200 });
function harness(script: Record<string, Array<() => Response | Promise<Response>>>) {
  const calls: string[] = [];
  const t = { now: 1_000_000 };
  const f = (async (url: string, init: any) => {
    const who = url.startsWith("https://g") ? "groq" : "openrouter";
    calls.push(`${who}:${JSON.parse(init.body).model}`);
    const next = script[who].shift();
    if (!next) throw new Error("no scripted response");
    return next();
  }) as any;
  return { llm: new FailoverLlm(P, f, 50, { now: () => t.now }), calls, t };
}

{ const h = harness({ groq: [() => reply("hi")], openrouter: [] });
  ok(await h.llm.complete("large", { prompt: "x" }) === "hi" && h.calls.join() === "groq:gl", "Groq healthy → Groq answers (large model)"); }
{ const h = harness({ groq: [() => new Response("Rate limit reached ... Please try again in 9.8s.", { status: 429 })], openrouter: [() => reply("from OR"), () => reply("again OR")] });
  const a = await h.llm.complete("small", { prompt: "x" });
  ok(a === "from OR" && h.calls.join() === "groq:gs,openrouter:os" && h.llm.stats.failovers === 1, "Groq 429 → same message answered by OpenRouter immediately");
  const b = await h.llm.complete("small", { prompt: "y" });
  ok(b === "again OR" && h.calls.length === 3 && h.calls[2] === "openrouter:os", "while Groq cools down (9.8 s hint) it is skipped, no wasted call");
  h.t.now += 11_000; (h as any).llm.providers; h.calls.length = 0;
}
{ const h = harness({ groq: [() => new Response("", { status: 429, headers: { "retry-after": "5" } }), () => reply("groq back")], openrouter: [() => reply("or")] });
  await h.llm.complete("small", { prompt: "x" }); h.t.now += 6_000;
  ok(await h.llm.complete("small", { prompt: "x" }) === "groq back", "after retry-after passes, Groq is used again"); }
{ const h = harness({ groq: [() => new Response("boom", { status: 503 })], openrouter: [() => reply("or")] });
  ok(await h.llm.complete("large", { prompt: "x" }) === "or", "Groq 5xx → OpenRouter"); }
{ const h = harness({ groq: [() => new Promise<Response>(() => {})], openrouter: [() => reply("or")] });
  const llm = new FailoverLlm(P, (async (url: string, init: any) => {
    if (url.startsWith("https://g")) return new Promise((_, rej) => init.signal.addEventListener("abort", () => rej(Object.assign(new Error("aborted"), { name: "AbortError" }))));
    return reply("or after timeout");
  }) as any, 50);
  ok(await llm.complete("large", { prompt: "x" }) === "or after timeout", "Groq hangs → times out → OpenRouter"); }
{ const h = harness({ groq: [() => new Response("", { status: 401 })], openrouter: [() => new Response("", { status: 429 })] });
  let msg = ""; try { await h.llm.complete("large", { prompt: "x" }); } catch (e: any) { msg = e.message; }
  ok(/All LLM providers failed/.test(msg) && /groq HTTP 401/.test(msg) && /openrouter rate limited/.test(msg), "both down → one clear error naming each provider"); }
{ const h = harness({ groq: [() => new Response(JSON.stringify({ choices: [{ message: { content: "" } }] }), { status: 200 })], openrouter: [() => reply("or")] });
  ok(await h.llm.complete("small", { prompt: "x" }) === "or", "empty answer counts as a failure → OpenRouter"); }
ok(JSON.stringify(parseJsonReply('```json\n{"a":1}\n```')) === '{"a":1}' && JSON.stringify(parseJsonReply('Sure! {"b":2} done')) === '{"b":2}', "parseJsonReply handles fences and prose");
ok(providersFromEnv({ GROQ_API_KEY: "g", OPENROUTER_API_KEY: "o" }).map((p) => p.name).join() === "groq,openrouter" && providersFromEnv({ OPENROUTER_API_KEY: "o" }).length === 1, "provider order: Groq first, OpenRouter second; either alone works");
console.log(`\n${pass}/${pass + fail} llm failover tests passed`);
if (fail) process.exit(1);
{ let body: any; const llm = new FailoverLlm([{ name: "openrouter", baseUrl: "https://o", apiKey: "o", small: "a:free", large: "a:free", fallbackModels: ["b:free", "a:free", "c:free", "d:free"] }], (async (_u: string, init: any) => { body = JSON.parse(init.body); return reply("ok"); }) as any);
  await llm.complete("large", { prompt: "x" });
  ok(body.model === "a:free" && JSON.stringify(body.models) === '["a:free","b:free","c:free"]', "OpenRouter gets a `models` list (primary first, no duplicates, max 3)");
  console.log(`  (total ${pass}/${pass + fail})`); if (fail) process.exit(1); }
{ const orig = console.warn; console.warn = () => {};
  const [or] = providersFromEnv({ OPENROUTER_API_KEY: "o", OPENROUTER_LARGE_MODEL: "openai/gpt-oss-120b", OPENROUTER_SMALL_MODEL: "google/gemma-4-31b-it:free", OPENROUTER_FALLBACK_MODELS: "anthropic/claude-x, nvidia/nemotron-3-ultra-550b-a55b:free" });
  console.warn = orig;
  ok(or.large === "nvidia/nemotron-3-super-120b-a12b:free" && or.small === "google/gemma-4-31b-it:free" && JSON.stringify(or.fallbackModels) === '["nvidia/nemotron-3-ultra-550b-a55b:free"]', "OpenRouter is free-only: paid models in settings are ignored");
  ok([or.small, or.large, ...(or.fallbackModels || [])].every((m) => m.endsWith(":free")) && [providersFromEnv({ OPENROUTER_API_KEY: "o" })[0]].every((p) => [p.small, p.large, ...(p.fallbackModels || [])].every((m) => m.endsWith(":free"))), "every OpenRouter model (defaults included) ends with :free");
  console.log(`  (total ${pass}/${pass + fail})`); if (fail) process.exit(1); }
