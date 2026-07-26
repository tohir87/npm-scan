import { mkdir, writeFile } from 'fs/promises';
import { join, isAbsolute, resolve } from 'path';
import { randomUUID } from 'crypto';
import type { FindingsReport } from './analyzer.js';

export type DatasetCategory = 'D_mal' | 'D_ben';
export type Classification = 'TP' | 'FP' | 'TN' | 'FN';
export type Verdict = 'blocked' | 'allowed' | 'error';

export const DEFAULT_LOG_DIR = 'eval_results/raw';

export interface RunLogEntry {
  // --- eval schema ---
  package_name: string;
  version: string | null;
  dataset_category: DatasetCategory | null;
  execution_time_ms: number;
  /** Every HTTP(S) URL found in the extracted package, deduped. */
  manifest_urls_found: string[];
  /** Reserved for the AST pass — the scanner is regex-only today, so always []. */
  ast_intents: string[];
  /** Reserved for the semantic-mismatch pass — not computed yet, so always null. */
  semantic_mismatch_detected: boolean | null;
  classification: Classification | null;
  error_log: string | null;

  // --- run metadata beyond the eval schema ---
  run_id: string;
  timestamp: string;
  spec: string;
  verdict: Verdict;
  detected_suspicious: boolean;
  installed: boolean;
  files_scanned: number;
  ips_found: string[];
  auto_run_scripts: string[];
  scripts: Record<string, string>;
}

/**
 * A package counts as "detected" when the scan surfaced anything the report
 * asks the user to review — remote URLs, IP literals, or auto-run lifecycle
 * hooks. This is the signal that gets scored against the dataset label.
 */
export function isDetected(report: FindingsReport): boolean {
  return report.urls.length > 0 || report.ips.length > 0 || report.autoRunScripts.length > 0;
}

export function classify(
  dataset: DatasetCategory | null,
  detected: boolean,
): Classification | null {
  if (dataset === null) return null;
  if (dataset === 'D_mal') return detected ? 'TP' : 'FN';
  return detected ? 'FP' : 'TN';
}

function dedupe(values: string[]): string[] {
  return [...new Set(values)];
}

export interface BuildLogInput {
  spec: string;
  report: FindingsReport | null;
  dataset: DatasetCategory | null;
  executionTimeMs: number;
  verdict: Verdict;
  installed: boolean;
  error: string | null;
}

export function buildRunLog(input: BuildLogInput): RunLogEntry {
  const { spec, report, dataset, executionTimeMs, verdict, installed, error } = input;
  const detected = report ? isDetected(report) : false;

  return {
    package_name: report?.spec ?? spec,
    version: report?.resolvedVersion ?? null,
    dataset_category: dataset,
    execution_time_ms: executionTimeMs,
    manifest_urls_found: report ? dedupe(report.urls.map((u) => u.match)) : [],
    ast_intents: [],
    semantic_mismatch_detected: null,
    // A run that never completed can't be scored either way.
    classification: report ? classify(dataset, detected) : null,
    error_log: error,

    run_id: randomUUID(),
    timestamp: new Date().toISOString(),
    spec,
    verdict,
    detected_suspicious: detected,
    installed,
    files_scanned: report?.filesScanned ?? 0,
    ips_found: report ? dedupe(report.ips.map((i) => i.match)) : [],
    auto_run_scripts: report?.autoRunScripts ?? [],
    scripts: report?.scripts ?? {},
  };
}

function safeName(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]/g, '_');
}

export function resolveLogDir(logDir: string): string {
  return isAbsolute(logDir) ? logDir : resolve(process.cwd(), logDir);
}

/**
 * Writes one JSON file per scanned package. Log failures are reported but never
 * thrown — a broken log directory must not take down an install.
 */
export async function writeRunLog(entry: RunLogEntry, logDir: string): Promise<string | null> {
  const dir = resolveLogDir(logDir);
  const stamp = entry.timestamp.replace(/[:.]/g, '-');
  const file = join(dir, `${stamp}__${safeName(entry.spec)}__${entry.run_id.slice(0, 8)}.json`);

  try {
    await mkdir(dir, { recursive: true });
    await writeFile(file, `${JSON.stringify(entry, null, 2)}\n`, 'utf8');
    return file;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[npm-scan] Warning: could not write run log to ${dir}: ${msg}`);
    return null;
  }
}
