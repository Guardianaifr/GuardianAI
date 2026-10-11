/**
 * Connect code: everything the agent needs from the GuardianAI console, in one copy-pasteable token.
 *   gx1_<base64url JSON {v,c,w,o,k}>   w = guarded wallet, o = owner, k = agent key (gas-only)
 * Kept dependency-free so the console (browser) and the CLI (node) share the same format.
 */
export interface ConnectInfo { wallet: string; owner: string; agentKey: string; chainId: number }

const PREFIX = "gx1_";
const ADDR = /^0x[0-9a-fA-F]{40}$/;
const KEY = /^0x[0-9a-fA-F]{64}$/;

const b64url = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64url = (s: string) => atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));

export function encodeConnectCode(i: ConnectInfo): string {
  if (!ADDR.test(i.wallet) || !ADDR.test(i.owner) || !KEY.test(i.agentKey)) throw new Error("encodeConnectCode: bad wallet/owner/key");
  return PREFIX + b64url(JSON.stringify({ v: 1, c: i.chainId, w: i.wallet, o: i.owner, k: i.agentKey }));
}

export function decodeConnectCode(code: string): ConnectInfo {
  const s = String(code || "").trim();
  if (!s.startsWith(PREFIX)) throw new Error("That isn't a GuardianAI connect code (it should start with gx1_). Copy it again from the console.");
  let d: any;
  try { d = JSON.parse(unb64url(s.slice(PREFIX.length))); } catch { throw new Error("The connect code is damaged. Copy it again from the console."); }
  if (d?.v !== 1 || !ADDR.test(d.w) || !ADDR.test(d.o) || !KEY.test(d.k)) throw new Error("The connect code is incomplete. Copy it again from the console.");
  return { wallet: d.w, owner: d.o, agentKey: d.k, chainId: Number(d.c) || 10143 };
}
