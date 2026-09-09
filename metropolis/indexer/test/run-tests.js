import { spawnSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const testPaths = [
  path.resolve(__dirname, 'EventHandlers.test.ts'),
  path.resolve(__dirname, 'EventHandlers.adversarial.test.ts')
];

for (const testPath of testPaths) {
  console.log(`[run-tests] Executing standalone TypeScript test suite: ${testPath}`);

  const result = spawnSync('node', [testPath], {
    stdio: 'inherit',
    shell: true,
    cwd: path.resolve(__dirname, '..')
  });

  if (result.status !== 0) {
    console.error(`[-] Tests failed with status: ${result.status}`);
    process.exit(result.status || 1);
  }
}

console.log('[run-tests] All indexer unit tests completed successfully.');