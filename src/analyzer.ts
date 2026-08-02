import pacote from 'pacote';
const { extract, manifest } = pacote;
import { readFile, readdir } from 'fs/promises';
import { join, relative, basename } from 'path';
import {
  classifyIp,
  classifyUrl,
  closesBlockComment,
  countBySeverity,
  findSinks,
  opensBlockComment,
  positionOfLine,
  type Position,
  type SeverityCounts,
  type UrlVerdict,
} from './classify.js';
import { deriveSelfOrigins, type SelfOrigin } from './origins.js';
import { checkOsv, type OsvResult } from './intel/osv.js';
import type { IntelOptions, IntelSource } from './intel/urlhaus.js';

export interface Occurrence {
  file: string;
  line: number;
  position: Position;
}

/** One distinct match, with every place it turned up and what the policy made of it. */
export interface Finding {
  match: string;
  occurrences: Occurrence[];
  verdict: UrlVerdict;
}

export interface FindingsReport {
  spec: string;
  /** The resolved package name — `spec` still carries whatever the user typed. */
  name: string;
  resolvedVersion: string;
  filesScanned: number;
  /** Unique URLs, first-seen order, each carrying its severity and the reasons for it. */
  urls: Finding[];
  /** Unique IP literals, first-seen order. */
  ips: Finding[];
  scripts: Record<string, string>;
  /** Root-manifest hooks npm executes on install — `preinstall`/`install`/`postinstall`. */
  autoRunScripts: string[];
  /** Root-manifest packaging hooks, which do not run for a registry tarball. */
  publishScripts: string[];
  severityCounts: SeverityCounts;
  /** Network/exec sinks seen next to a finding — the regex stand-in for an AST pass. */
  sinks: string[];
  selfOrigins: SelfOrigin[];
  osv: OsvResult;
  intelSources: IntelSourceStatus[];
}

export interface IntelSourceStatus {
  name: string;
  status: 'ready' | 'unavailable';
  reason: string | null;
  fetchedAt: string | null;
  entryCount: number;
}

/** A single raw hit, before matches are collapsed and judged. */
interface RawMatch {
  match: string;
  file: string;
  line: number;
  position: Position;
  sinks: string[];
}

/**
 * Collects matches keyed by the matched string, so a URL repeated across files
 * (or bundled three times into one file) is reported once, with its locations,
 * and is judged at the worst position it was seen in.
 */
class FindingSet {
  private readonly byMatch = new Map<
    string,
    { occurrences: Occurrence[]; positions: Position[]; sinks: Set<string> }
  >();

  add(raw: RawMatch): void {
    let entry = this.byMatch.get(raw.match);
    if (!entry) {
      entry = { occurrences: [], positions: [], sinks: new Set() };
      this.byMatch.set(raw.match, entry);
    }

    entry.positions.push(raw.position);
    for (const sink of raw.sinks) entry.sinks.add(sink);

    // Same match twice on one line is one occurrence, not two.
    if (entry.occurrences.some((o) => o.file === raw.file && o.line === raw.line)) return;
    entry.occurrences.push({ file: raw.file, line: raw.line, position: raw.position });
  }

  /** Judges every collected match with `judge`, preserving first-seen order. */
  resolve(judge: (match: string, positions: Position[], sinks: string[]) => UrlVerdict): Finding[] {
    return [...this.byMatch.entries()].map(([match, entry]) => ({
      match,
      occurrences: entry.occurrences,
      verdict: judge(match, entry.positions, [...entry.sinks]),
    }));
  }
}

export function countOccurrences(findings: Finding[]): number {
  return findings.reduce((total, f) => total + f.occurrences.length, 0);
}

/**
 * The hooks npm runs on your machine when it installs a published tarball. These are
 * the ones that matter for a consumer: arbitrary code, executed before you have run
 * anything yourself.
 */
export const INSTALL_HOOKS = new Set(['preinstall', 'install', 'postinstall']);

/**
 * Packaging hooks. They fire when publishing, or when a dependency is installed from
 * a git URL — not when npm unpacks a registry tarball. Treating them as install-time
 * execution overstates the risk of the many packages that define `prepare`.
 */
export const PUBLISH_HOOKS = new Set(['prepare', 'prepublish', 'prepack', 'postpack']);

export const AUTO_RUN_HOOKS = new Set([...INSTALL_HOOKS, ...PUBLISH_HOOKS]);

const SCANNABLE_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.json']);

const H16 = '[0-9a-fA-F]{1,4}';

/**
 * Host forms a real URL can have. Requiring one of these is what separates a
 * callback from a bundler artefact — `https://$1/` and `https://$` have no host
 * at all, so they no longer match.
 *
 * Labels are a flat `{1,63}` class rather than the stricter
 * "no leading/trailing hyphen" form on purpose: the strict version nests
 * quantifiers, which backtracks exponentially on crafted input. This scanner
 * reads untrusted package code, so a bounded pattern beats a pedantic one.
 */
const URL_HOST = [
  `\\[(?:${H16}:|:){2,7}(?:${H16})?\\]`,              // bracketed IPv6, e.g. [::1]
  '(?:\\d{1,3}\\.){3}\\d{1,3}',                        // IPv4 literal
  '(?:[a-zA-Z0-9-]{1,63}\\.)+[a-zA-Z]{2,63}',          // domain with a real TLD
  'localhost',
].join('|');

// Everything a path/query/fragment may contain — stops at whitespace and
// common string-terminating characters.
const URL_TAIL = "[^\\s'\"`<>\\\\\\[\\](){}]";

// HTTP/HTTPS URLs: scheme, optional userinfo, a plausible host, optional port, optional tail
const URL_PATTERN = new RegExp(
  `https?://(?:[^\\s/@]+@)?(?:${URL_HOST})(?::\\d{1,5})?(?:[/?#]${URL_TAIL}*)?`,
  'g',
);

// Punctuation that clings to the end of a URL in prose or code but isn't part of it
const URL_TRAILING_JUNK = /[.,;:!?'$&=-]+$/;

// IPv4 — strict per-octet 0-255 range, all 4 octets required. The lookarounds
// reject a slice of a longer dotted-numeric run, so `1.2.3.4.5` (a version
// string, not an address) matches nothing, while `10.0.0.1.` at the end of a
// sentence still matches.
const IPV4_PATTERN =
  /(?<![\w.])((?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d))(?!\w|\.\d)/g;

/**
 * IPv6 — the full 8-group form, or a compressed form that actually contains
 * `::`. The previous pattern allowed any 3-to-8 colon-separated hex run, which
 * matched minified-code fragments like `3:2:1`. Every compressed alternative
 * below requires a `::`, so those are gone. The bare `::` form is deliberately
 * omitted: it carries no signal and collides with CSS pseudo-elements.
 */
const IPV6_FORMS = [
  `(?:${H16}:){7}${H16}`, //            1:2:3:4:5:6:7:8
  `(?:${H16}:){1,7}:`, //               1::            1:2:3:4:5:6:7::
  `(?:${H16}:){1,6}:${H16}`, //         1::8           1:2:3:4:5:6::8
  `(?:${H16}:){1,5}(?::${H16}){1,2}`, // 1::7:8
  `(?:${H16}:){1,4}(?::${H16}){1,3}`,
  `(?:${H16}:){1,3}(?::${H16}){1,4}`,
  `(?:${H16}:){1,2}(?::${H16}){1,5}`,
  `${H16}:(?::${H16}){1,6}`, //         1::3:4:5:6:7:8
  `:(?::${H16}){1,7}`, //               ::8  ::1
];
const IPV6_PATTERN = new RegExp(`(?<![.:\\w])(?:${IPV6_FORMS.join('|')})(?![.:\\w])`, 'g');

/** Pulls every URL and IP literal out of a single line. Pure — safe to test directly. */
export function extractFromLine(line: string): { urls: string[]; ips: string[] } {
  const urls: string[] = [];
  const ips: string[] = [];
  let m: RegExpExecArray | null;

  URL_PATTERN.lastIndex = 0;
  while ((m = URL_PATTERN.exec(line)) !== null) {
    const url = m[0].replace(URL_TRAILING_JUNK, '');
    if (url.length > 0) urls.push(url);
  }

  IPV4_PATTERN.lastIndex = 0;
  while ((m = IPV4_PATTERN.exec(line)) !== null) {
    ips.push(m[1]);
  }

  IPV6_PATTERN.lastIndex = 0;
  while ((m = IPV6_PATTERN.exec(line)) !== null) {
    ips.push(m[0]);
  }

  return { urls, ips };
}

function getExt(filename: string): string {
  const dot = filename.lastIndexOf('.');
  return dot >= 0 ? filename.slice(dot) : '';
}

/** Best-effort line number for a match found via the JSON tree rather than the text. */
function findLine(lines: string[], needle: string): number {
  const index = lines.findIndex((line) => line.includes(needle));
  return index >= 0 ? index + 1 : 1;
}

/**
 * Walks a package.json as a document instead of as text. This is the change that
 * ends the false-positive problem: `repository`, `homepage` and `bugs` are metadata
 * fields, and a URL in one of them is a string in a manifest, not a network call.
 * Only `scripts` values are commands, and those are tagged by whether npm runs them
 * for you.
 */
function collectFromPackageJson(content: string, relPath: string, isRoot: boolean, into: {
  urls: FindingSet;
  ips: FindingSet;
}): Record<string, string> | null {
  let parsed: { scripts?: Record<string, string> } & Record<string, unknown>;
  try {
    parsed = JSON.parse(content) as typeof parsed;
  } catch {
    return null;
  }

  const lines = content.split('\n');

  const collect = (value: string, position: Position, sinks: string[]): void => {
    const found = extractFromLine(value);
    const line = findLine(lines, value);
    for (const url of found.urls) into.urls.add({ match: url, file: relPath, line, position, sinks });
    for (const ip of found.ips) into.ips.add({ match: ip, file: relPath, line, position, sinks });
  };

  const walk = (node: unknown): void => {
    if (typeof node === 'string') return collect(node, 'metadata', []);
    if (Array.isArray(node)) return node.forEach(walk);
    if (node && typeof node === 'object') {
      for (const [key, value] of Object.entries(node)) {
        if (key !== 'scripts') walk(value);
      }
    }
  };

  const scripts = parsed.scripts && typeof parsed.scripts === 'object' ? parsed.scripts : {};
  for (const [name, command] of Object.entries(scripts)) {
    if (typeof command !== 'string') continue;
    // Only the root manifest's hooks are the ones npm executes. A bundled nested
    // manifest's `postinstall` never runs, so it must not carry the same weight.
    const position: Position = isRoot && INSTALL_HOOKS.has(name) ? 'script-hook' : 'script-manual';
    collect(command, position, findSinks([command], 0));
  }

  walk(parsed);

  return scripts as Record<string, string>;
}

/** Scans an ordinary source file line by line, tagging each line's position. */
function collectFromSource(content: string, relPath: string, isJson: boolean, into: {
  urls: FindingSet;
  ips: FindingSet;
}): void {
  const lines = content.split('\n');
  let inBlockComment = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const inComment = inBlockComment || opensBlockComment(line);

    // Advance the block-comment state before the early exit below, so a licence
    // banner with no URLs in it still closes correctly.
    if (inBlockComment) {
      if (closesBlockComment(line)) inBlockComment = false;
    } else if (opensBlockComment(line) && !closesBlockComment(line.slice(line.indexOf('/*') + 2))) {
      inBlockComment = true;
    }

    const found = extractFromLine(line);
    if (found.urls.length === 0 && found.ips.length === 0) continue;

    // A .json file has no comments and no call sites — it is data that code may
    // read, so it counts as reachable but never carries a sink of its own.
    const position: Position = isJson ? 'code' : inComment ? 'comment' : positionOfLine(line);
    const sinks = isJson ? [] : findSinks(lines, i);

    for (const url of found.urls) {
      into.urls.add({ match: url, file: relPath, line: i + 1, position, sinks });
    }
    for (const ip of found.ips) {
      into.ips.add({ match: ip, file: relPath, line: i + 1, position, sinks });
    }
  }
}

export interface ScanContext {
  urlhaus: IntelSource;
  intelOptions: IntelOptions;
}

export async function fetchAndScan(
  spec: string,
  tempDir: string,
  context: ScanContext,
): Promise<FindingsReport> {
  // `fullMetadata` is required, not optional: the abbreviated manifest pacote returns
  // by default omits `repository`, `homepage` and `bugs` — the exact fields the
  // provenance check needs to recognise a package's own URLs.
  const pkg = await manifest(spec, { fullMetadata: true });
  const resolvedVersion: string = pkg.version;
  const selfOrigins = deriveSelfOrigins(pkg);

  await extract(spec, tempDir, { ignoreScripts: true });

  const entries = await readdir(tempDir, { recursive: true, withFileTypes: true });
  const files = entries
    .filter((e) => e.isFile() && SCANNABLE_EXTENSIONS.has(getExt(e.name)))
    // parentPath is Node >=20.12; earlier versions use path
    .map((e) => join((e as NodeDirentCompat).parentPath ?? (e as NodeDirentCompat).path, e.name));

  const into = { urls: new FindingSet(), ips: new FindingSet() };
  let scripts: Record<string, string> = {};

  for (const filePath of files) {
    const relPath = relative(tempDir, filePath);
    let content: string;
    try {
      content = await readFile(filePath, 'utf8');
    } catch {
      continue;
    }

    if (basename(relPath) === 'package.json') {
      const isRoot = relPath === 'package.json';
      const found = collectFromPackageJson(content, relPath, isRoot, into);
      if (found && isRoot) scripts = found;
      continue;
    }

    collectFromSource(content, relPath, getExt(relPath) === '.json', into);
  }

  const osv = await checkOsv(pkg.name, resolvedVersion, context.intelOptions);

  const urls = into.urls.resolve((match, positions, sinks) =>
    classifyUrl({ url: match, positions, sinks, selfOrigins, intel: context.urlhaus.lookup(match) }),
  );
  const ips = into.ips.resolve((match, positions, sinks) => classifyIp({ ip: match, positions, sinks }));

  const autoRunScripts = Object.keys(scripts).filter((name) => INSTALL_HOOKS.has(name));
  const publishScripts = Object.keys(scripts).filter((name) => PUBLISH_HOOKS.has(name));
  const severityCounts = countBySeverity([...urls, ...ips].map((f) => f.verdict.severity));

  // A known-malicious package is a fact about the artefact, not about any one URL,
  // so it is counted straight into the critical tally.
  severityCounts.critical += osv.advisories.filter((a) => a.malicious).length;

  // An install hook is a finding in its own right, independent of any URL: it runs
  // arbitrary code on the machine before anything has been imported. The URL rules
  // can't see a download whose address is built at runtime, which is exactly what
  // binary-fetching postinstall scripts do — so the hook itself has to be the signal.
  if (autoRunScripts.length > 0) severityCounts.warn += 1;

  const sinks = [...new Set([...urls, ...ips].flatMap((f) => f.verdict.sinks))];

  return {
    spec,
    name: pkg.name,
    resolvedVersion,
    filesScanned: files.length,
    urls,
    ips,
    scripts,
    autoRunScripts,
    publishScripts,
    severityCounts,
    sinks,
    selfOrigins,
    osv,
    intelSources: [
      {
        name: context.urlhaus.name,
        status: context.urlhaus.status,
        reason: context.urlhaus.reason,
        fetchedAt: context.urlhaus.fetchedAt,
        entryCount: context.urlhaus.entryCount,
      },
      {
        name: 'osv',
        status: osv.status,
        reason: osv.reason,
        fetchedAt: osv.checkedAt,
        entryCount: osv.advisories.length,
      },
    ],
  };
}

// Compatibility shim for Dirent.parentPath vs Dirent.path across Node versions
interface NodeDirentCompat {
  parentPath: string;
  path: string;
}
