import { mkdtemp, rm } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { passthroughToNpm, runNpmInstall } from './installer.js';
import { fetchAndScan, type FindingsReport, type ScanContext } from './analyzer.js';
import { presentFindings } from './prompt.js';
import { loadUrlhaus, type IntelOptions } from './intel/urlhaus.js';
import { loadDotEnv } from './env.js';
import {
  buildRunLog,
  writeRunLog,
  DEFAULT_LOG_DIR,
  type DatasetCategory,
  type Verdict,
} from './logger.js';

const INSTALL_CMDS = new Set(['install', 'i']);
const DATASET_CATEGORIES = new Set<DatasetCategory>(['D_mal', 'D_ben']);
const DEFAULT_INTEL_TIMEOUT_MS = 3000;

interface ScanOptions {
  /** Ground-truth label for the run; drives TP/FP/TN/FN classification. */
  dataset: DatasetCategory | null;
  interactive: boolean;
  /** Scan and log only — never hand over to npm install. */
  scanOnly: boolean;
  logging: boolean;
  logDir: string;
  intel: IntelOptions;
}

function parseDataset(value: string | undefined): DatasetCategory | null {
  if (!value) return null;
  if (!DATASET_CATEGORIES.has(value as DatasetCategory)) {
    throw new Error(`Invalid dataset category "${value}" — expected D_mal or D_ben.`);
  }
  return value as DatasetCategory;
}

/**
 * Splits install arguments into package specs, npm-scan's own options, and the
 * remaining flags to forward to npm. npm-scan flags are consumed here so they
 * never leak into the real install command.
 */
function parseArgs(rest: string[]): { specs: string[]; npmFlags: string[]; options: ScanOptions } {
  const options: ScanOptions = {
    dataset: parseDataset(process.env.NPM_SCAN_DATASET),
    interactive: process.env.NPM_SCAN_NONINTERACTIVE !== '1',
    scanOnly: process.env.NPM_SCAN_SCAN_ONLY === '1',
    logging: process.env.NPM_SCAN_LOG !== '0',
    logDir: process.env.NPM_SCAN_LOG_DIR || DEFAULT_LOG_DIR,
    intel: {
      offline: process.env.NPM_SCAN_OFFLINE === '1',
      refresh: false,
      timeoutMs: Number(process.env.NPM_SCAN_INTEL_TIMEOUT) || DEFAULT_INTEL_TIMEOUT_MS,
    },
  };

  const specs: string[] = [];
  const npmFlags: string[] = [];

  for (const arg of rest) {
    if (arg.startsWith('--dataset=')) {
      options.dataset = parseDataset(arg.slice('--dataset='.length));
    } else if (arg.startsWith('--log-dir=')) {
      options.logDir = arg.slice('--log-dir='.length);
    } else if (arg === '--no-log') {
      options.logging = false;
    } else if (arg === '--no-prompt') {
      options.interactive = false;
    } else if (arg === '--scan-only') {
      options.scanOnly = true;
      options.interactive = false;
    } else if (arg === '--offline') {
      options.intel.offline = true;
    } else if (arg === '--refresh-intel') {
      options.intel.refresh = true;
    } else if (arg.startsWith('--intel-timeout=')) {
      const ms = Number(arg.slice('--intel-timeout='.length));
      if (!Number.isFinite(ms) || ms <= 0) {
        throw new Error(`Invalid --intel-timeout "${arg}" — expected a positive number of milliseconds.`);
      }
      options.intel.timeoutMs = ms;
    } else if (arg.startsWith('-')) {
      npmFlags.push(arg);
    } else {
      specs.push(arg);
    }
  }

  return { specs, npmFlags, options };
}

interface ScanOutcome {
  proceed: boolean;
  failed: boolean;
}

async function scanOne(
  spec: string,
  options: ScanOptions,
  context: ScanContext,
): Promise<ScanOutcome> {
  const tempDir = await mkdtemp(join(tmpdir(), 'npm-scan-'));
  const started = Date.now();

  let report: FindingsReport | null = null;
  let error: string | null = null;
  let executionTimeMs = 0;

  try {
    console.log(`\n[npm-scan] Fetching ${spec} for inspection...`);
    report = await fetchAndScan(spec, tempDir, context);
    executionTimeMs = Date.now() - started;
  } catch (err) {
    executionTimeMs = Date.now() - started;
    error = err instanceof Error ? err.message : String(err);
    console.error(`\n[npm-scan] Error scanning ${spec}: ${error}`);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }

  const proceed = report ? await presentFindings(report, { interactive: options.interactive }) : false;
  const verdict: Verdict = error ? 'error' : proceed ? 'allowed' : 'blocked';

  if (options.logging) {
    const entry = buildRunLog({
      spec,
      report,
      dataset: options.dataset,
      executionTimeMs,
      verdict,
      installed: proceed && !options.scanOnly,
      error,
    });
    const path = await writeRunLog(entry, options.logDir);
    if (path) console.log(`[npm-scan] Run log: ${path}`);
  }

  return { proceed, failed: error !== null };
}

async function main(): Promise<void> {
  // Before parseArgs, which reads its defaults straight out of process.env.
  loadDotEnv();

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

  const { specs, npmFlags, options } = parseArgs(rest);

  // Bare `npm install` (installs from package.json) — pass through unchanged
  if (specs.length === 0) {
    passthroughToNpm(args);
    return;
  }

  // Loaded once for the whole invocation: a sweep of a thousand specs answers every
  // URL from one cached feed rather than a request per package.
  const urlhaus = await loadUrlhaus(options.intel);
  const context: ScanContext = { urlhaus, intelOptions: options.intel };

  let anyFailed = false;
  for (const spec of specs) {
    const { proceed, failed } = await scanOne(spec, options, context);
    anyFailed ||= failed;

    // In scan-only mode every spec gets scanned and logged, whatever the verdict.
    if (options.scanOnly) continue;

    if (failed) process.exit(1);
    if (!proceed) {
      console.log('[npm-scan] Installation cancelled.');
      process.exit(0);
    }
  }

  if (options.scanOnly) {
    console.log('\n[npm-scan] Scan-only mode — no install performed.');
    process.exit(anyFailed ? 1 : 0);
  }

  runNpmInstall(['install', ...specs, ...npmFlags]);
}

main().catch((err: Error) => {
  const msg = err?.message ?? String(err);
  console.error(`\n[npm-scan] Error: ${msg}`);
  process.exit(1);
});
