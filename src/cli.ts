import { mkdtemp, rm } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { passthroughToNpm, runNpmInstall } from './installer.js';
import { fetchAndScan } from './analyzer.js';
import { presentFindings } from './prompt.js';

const INSTALL_CMDS = new Set(['install', 'i']);

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    passthroughToNpm([]);
    return;
  }

  const [command, ...rest] = args;

  if (!INSTALL_CMDS.has(command)) {
    passthroughToNpm(args);
    return;
  }

  const flags: string[] = [];
  const specs: string[] = [];
  for (const arg of rest) {
    if (arg.startsWith('-')) {
      flags.push(arg);
    } else {
      specs.push(arg);
    }
  }

  // Bare `npm install` (installs from package.json) — pass through unchanged
  if (specs.length === 0) {
    passthroughToNpm(args);
    return;
  }

  for (const spec of specs) {
    const tempDir = await mkdtemp(join(tmpdir(), 'npm-scan-'));
    try {
      console.log(`\n[npm-scan] Fetching ${spec} for inspection...`);
      const report = await fetchAndScan(spec, tempDir);
      const proceed = await presentFindings(report);
      if (!proceed) {
        console.log('[npm-scan] Installation cancelled.');
        process.exit(0);
      }
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  }

  runNpmInstall(['install', ...specs, ...flags]);
}

main().catch((err: Error) => {
  const msg = err?.message ?? String(err);
  console.error(`\n[npm-scan] Error: ${msg}`);
  process.exit(1);
});
