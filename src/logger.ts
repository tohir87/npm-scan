import { mkdir, writeFile } from 'fs/promises';
import { join, isAbsolute, resolve } from 'path';
import { randomUUID } from 'crypto';
import type { Finding, FindingsReport, IntelSourceStatus } from './analyzer.js';
import type { Position, Severity, SeverityCounts } from './classify.js';
import type { Provenance } from './origins.js';

export type DatasetCategory = 'D_mal' | 'D_ben';
export type Classification = 'TP' | 'FP' | 'TN' | 'FN';
export type Verdict = 'blocked' | 'allowed' | 'error';

export const DEFAULT_LOG_DIR = 'eval_results/raw';

/** One judged finding, flattened for downstream aggregation. */
export interface FindingLogEntry {
  match: string;
  severity: Severity;
  position: Position;
  provenance: Provenance;
  sinks: string[];
  reasons: string[];
  occurrences: number;
  first_seen: string;
}

export interface RunLogEntry {
  // --- eval schema ---
  package_name: string;
  version: string | null;
  dataset_category: DatasetCategory | null;
  execution_time_ms: number;
  /** Every HTTP(S) URL found in the extracted package, deduped. */
  manifest_urls_found: string[];
  /**
   * Network and process sinks found next to a finding. Still a regex proximity
   * check rather than a real AST pass, but no longer an empty placeholder.
   */
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
  /** Hooks npm runs when installing this tarball — the ones that execute on your machine. */
  auto_run_scripts: string[];
  /** Packaging hooks, which do not run for a registry install. */
  publish_scripts: string[];
  scripts: Record<string, string>;

  // --- classification detail ---
  severity_counts: SeverityCounts;
  /** Per-URL and per-IP verdicts with the rules that produced them. */
  url_findings: FindingLogEntry[];
  ip_findings: FindingLogEntry[];
  /** Hosts derived from the package's own manifest, used to declassify self-references. */
  self_origins: Array<{ host: string; owner: string | null; field: string }>;
  osv_advisories: Array<{ id: string; summary: string; malicious: boolean }>;
  /**
   * Which feed each verdict was drawn from and when it was downloaded. Without this
   * a threat-intel-dependent result can't be reproduced or compared across sweeps.
   */
  intel_snapshot: IntelSourceStatus[];
}

/**
 * A package counts as "detected" when the scan produced at least one finding worth
 * a human decision — a critical or a warning.
 *
 * This replaces "any URL, IP or lifecycle hook is a detection". That predicate fired
 * on essentially every published package, because every package declares a repository
 * URL, which made the FP and TN columns of an eval sweep meaningless.
 */
export function isDetected(report: FindingsReport): boolean {
  return report.severityCounts.critical > 0 || report.severityCounts.warn > 0;
}

function toFindingLog(finding: Finding): FindingLogEntry {
  const first = finding.occurrences[0];
  return {
    match: finding.match,
    severity: finding.verdict.severity,
    position: finding.verdict.position,
    provenance: finding.verdict.provenance,
    sinks: finding.verdict.sinks,
    reasons: finding.verdict.reasons,
    occurrences: finding.occurrences.length,
    first_seen: first ? `${first.file}:${first.line}` : '',
  };
}

export function classify(
  dataset: DatasetCategory | null,
  detected: boolean,
): Classification | null {
  if (dataset === null) return null;
  if (dataset === 'D_mal') return detected ? 'TP' : 'FN';
  return detected ? 'FP' : 'TN';
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
    package_name: report?.name ?? spec,
    version: report?.resolvedVersion ?? null,
    dataset_category: dataset,
    execution_time_ms: executionTimeMs,
    // Already unique — the analyzer collapses repeats.
    manifest_urls_found: report ? report.urls.map((u) => u.match) : [],
    ast_intents: report?.sinks ?? [],
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
    ips_found: report ? report.ips.map((i) => i.match) : [],
    auto_run_scripts: report?.autoRunScripts ?? [],
    publish_scripts: report?.publishScripts ?? [],
    scripts: report?.scripts ?? {},

    severity_counts: report?.severityCounts ?? { critical: 0, warn: 0, info: 0 },
    url_findings: report ? report.urls.map(toFindingLog) : [],
    ip_findings: report ? report.ips.map(toFindingLog) : [],
    self_origins: report?.selfOrigins ?? [],
    osv_advisories: report?.osv.advisories ?? [],
    intel_snapshot: report?.intelSources ?? [],
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
