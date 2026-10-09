// Bundles src/operator_console.ts into website/mera/app.js (static page, no server needed).
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const outfile = path.resolve(here, '../../../website/mera/app.js');
await build({
  entryPoints: [path.resolve(here, '../src/operator_console.ts')],
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: ['chrome120', 'safari17', 'firefox120'],
  minify: true,
  sourcemap: false,
  legalComments: 'eof',
  outfile,
});
console.log(`built ${path.relative(process.cwd(), outfile)}`);
