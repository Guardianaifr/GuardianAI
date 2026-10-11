// Tiny .env loader (no dependency): repo-root .env, then this folder's .env.agent (written by setup.mjs).
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
export const here = path.dirname(fileURLToPath(import.meta.url))
export const AGENT_ENV = path.join(here, '.env.agent')
export function loadEnv() {
  for (const f of [path.resolve(here, '../../../../.env'), AGENT_ENV]) {
    if (!fs.existsSync(f)) continue
    for (const line of fs.readFileSync(f, 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/)
      if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '')
    }
  }
}
