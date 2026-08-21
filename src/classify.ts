import {
  classifyOrigin,
  hasExecutablePath,
  hasNonStandardPort,
  isLoopbackHost,
  isPrivateIpHost,
  isPinnedPackageCdn,
  isPunycodeHost,
  isRawIpHost,
  matchAbuseInfrastructure,
  parseUrlParts,
  type Provenance,
  type SelfOrigin,
} from './origins.js';

export type Severity = 'critical' | 'warn' | 'info';

/**
 * Where in the package a URL was found. This is the signal the old scanner had no
 * concept of, and the single biggest source of its false positives: a URL in the
 * `repository` field of package.json is a string in a metadata document, while the
 * same URL in a `postinstall` command is a network call that fires on install.
 */
export type Position = 'script-hook' | 'code' | 'script-manual' | 'comment' | 'sourcemap' | 'metadata';

/** Higher wins. A URL seen in several places is judged at its worst one. */
const POSITION_RANK: Record<Position, number> = {
  'script-hook': 5,
  code: 4,
  'script-manual': 3,
  comment: 2,
  sourcemap: 1,
  metadata: 0,
};

const INERT_POSITIONS = new Set<Position>(['metadata', 'comment', 'sourcemap']);

/** Positions where a match is a string in a document, not something that runs. */
export function isInertPosition(position: Position): boolean {
  return INERT_POSITIONS.has(position);
}

export function worstPosition(positions: Position[]): Position {
  return positions.reduce(
    (worst, p) => (POSITION_RANK[p] > POSITION_RANK[worst] ? p : worst),
    'metadata' as Position,
  );
}

/**
 * Tokens that turn a URL string into a network or process call. Matching these near
 * a URL is a regex-level stand-in for the reachability question an AST pass would
 * answer properly — it is why `ast_intents` in the run log can finally carry values.
 */
const SINK_PATTERNS: Array<[name: string, pattern: RegExp]> = [
  ['fetch', /\bfetch\s*\(/],
  ['axios', /\baxios\b/],
  ['http.get', /\bhttps?\.get\s*\(/],
  ['http.request', /\bhttps?\.request\s*\(/],
  ['got', /\bgot\s*[.(]/],
  ['request', /\brequest\s*\(/],
  ['superagent', /\bsuperagent\b/],
  ['node-fetch', /\bnode-fetch\b/],
  ['XMLHttpRequest', /\bXMLHttpRequest\b/],
  ['WebSocket', /\bWebSocket\s*\(/],
  ['net.connect', /\bnet\.(connect|createConnection)\s*\(/],
  ['child_process', /\bchild_process\b/],
  // `.exec(` is RegExp.prototype.exec, which appears in almost every parser in the
  // registry — matching it made moment's deprecation-notice URLs look like callbacks.
  // Only a bare `exec(` (a destructured child_process import) counts.
  ['exec', /\bexec(File)?Sync\s*\(|\bexecFile\s*\(|(?<![.\w])exec\s*\(/],
  ['spawn', /\bspawnSync\s*\(|\bspawn\s*\(/],
  ['curl', /\bcurl\s/],
  ['wget', /\bwget\s/],
  ['Invoke-WebRequest', /\bInvoke-WebRequest\b/i],
  ['importScripts', /\bimportScripts\s*\(/],
];

/** How many lines either side of a match count as "near". */
const SINK_WINDOW = 2;

/**
 * Sinks on the URL's own line, or within a couple of lines of it. Minified bundles
 * put everything on one line, so the same-line case does most of the work; the
 * window catches the readable `const url = "..."` / `fetch(url)` shape.
 */
export function findSinks(lines: string[], lineIndex: number): string[] {
  const start = Math.max(0, lineIndex - SINK_WINDOW);
  const end = Math.min(lines.length - 1, lineIndex + SINK_WINDOW);
  const found = new Set<string>();

  for (let i = start; i <= end; i++) {
    for (const [name, pattern] of SINK_PATTERNS) {
      if (pattern.test(lines[i])) found.add(name);
    }
  }

  return [...found];
}

/**
 * Module loaders: the argument they are given is not fetched, it is *executed*. A URL
 * here is a remote dynamic dependency — the package ships an address instead of the
 * code, and whatever answers that address runs in-process with full privileges the
 * moment the module is imported. Nothing about the installed tarball tells you what
 * that code is, and it can differ per download.
 *
 * Each pattern captures the specifier string so the match can be checked against it.
 * Proximity is not good enough for this rule: `require('fs')` sits at the top of
 * nearly every file, so a windowed check would make any URL near it look like a
 * remote load. The URL has to be the argument.
 */
const CODE_LOAD_CALLS: Array<[name: string, pattern: RegExp]> = [
  ['require', /\brequire\s*\(\s*(['"`])([^'"`\n]*)\1/g],
  ['import()', /\bimport\s*\(\s*(['"`])([^'"`\n]*)\1/g],
  ['importScripts', /\bimportScripts\s*\(\s*(['"`])([^'"`\n]*)\1/g],
  ['new Worker', /\bnew\s+Worker\s*\(\s*(['"`])([^'"`\n]*)\1/g],
  ['import from', /\b(?:import|export)\b[^;\n]*?\bfrom\s*(['"`])([^'"`\n]*)\1/g],
  ['import', /\bimport\s+(['"`])([^'"`\n]*)\1/g],
];

/**
 * Loaders on this line whose specifier contains `match`. Substring rather than
 * equality because the IP scan reports `1.2.3.4` for a specifier of
 * `http://1.2.3.4/p.js`, and the URL scan strips trailing punctuation.
 */
export function findCodeLoads(line: string, match: string): string[] {
  if (!line.includes(match)) return [];
  const found = new Set<string>();

  for (const [name, pattern] of CODE_LOAD_CALLS) {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(line)) !== null) {
      if (m[2].includes(match)) found.add(name);
    }
  }

  return [...found];
}

/**
 * Loaders whose specifier is not a literal string: `require(u)`, `import(base + p)`.
 * The URL is somewhere else — usually a variable one line up — so this can only ever
 * be a proximity guess, and it feeds the sink rules rather than the code-load rule.
 */
const DYNAMIC_LOAD_CALLS: Array<[name: string, pattern: RegExp]> = [
  ['require(dynamic)', /\brequire\s*\(\s*[^'"`\s)]/g],
  ['import(dynamic)', /\bimport\s*\(\s*[^'"`\s)]/g],
];

/**
 * How far from the URL a dynamic loader still counts as related, in characters.
 *
 * Characters, not lines, because a line is not a unit of distance in published code:
 * prettier ships a 532,000-character bundle whose line 11 holds both TypeScript's
 * `aka.ms` diagnostic URLs and a `require(t)` some 99,000 characters away. A
 * line-window called those related and warned on all four URLs. A character window
 * is the same proximity idea measured in something that means the same thing in a
 * minified bundle as it does in readable source.
 */
const LOAD_CHAR_WINDOW = 200;

function offsetsOf(haystack: string, needle: string): number[] {
  const offsets: number[] = [];
  for (let i = haystack.indexOf(needle); i !== -1; i = haystack.indexOf(needle, i + 1)) {
    offsets.push(i);
  }
  return offsets;
}

/** Dynamic loaders within `LOAD_CHAR_WINDOW` characters of `match`. */
export function findDynamicLoads(lines: string[], lineIndex: number, match: string): string[] {
  const start = Math.max(0, lineIndex - SINK_WINDOW);
  const end = Math.min(lines.length - 1, lineIndex + SINK_WINDOW);
  const text = lines.slice(start, end + 1).join('\n');

  const matchOffsets = offsetsOf(text, match);
  if (matchOffsets.length === 0) return [];

  const found = new Set<string>();
  for (const [name, pattern] of DYNAMIC_LOAD_CALLS) {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(text)) !== null) {
      if (matchOffsets.some((offset) => Math.abs(m!.index - offset) <= LOAD_CHAR_WINDOW)) {
        found.add(name);
        break;
      }
    }
  }

  return [...found];
}

const SOURCEMAP_DIRECTIVE = /\/\/[#@]\s*source(Mapping)?URL=/;
const COMMENT_LINE = /^\s*(\/\/|\/\*|\*|#)/;

/** Classifies a line of a source file. package.json positions come from the JSON walk. */
export function positionOfLine(line: string): Position {
  if (SOURCEMAP_DIRECTIVE.test(line)) return 'sourcemap';
  if (COMMENT_LINE.test(line)) return 'comment';
  return 'code';
}

/**
 * Licence banners are the common case a line-at-a-time check gets wrong: a
 * `/*! ... *​/` block whose body lines carry no leading `*` reads as code, which is
 * how TypeScript's Apache header ends up looking like a plaintext callback.
 *
 * The open is anchored to the start of a line rather than found anywhere in it. An
 * unanchored scan would let a package hide a URL behind a `/*` inside a string
 * literal and have it treated as an inert comment.
 */
export function opensBlockComment(line: string): boolean {
  return /^\s*\/\*/.test(line);
}

export function closesBlockComment(line: string): boolean {
  return line.includes('*/');
}

export interface IntelHit {
  source: string;
  detail: string;
  /**
   * `exact` is the listed URL itself; `host` is another URL on a host that has
   * distributed malware. The second is real signal but blanket-blocking on it would
   * punish a package for sharing a host with something bad, so it only warns.
   */
  confidence: 'exact' | 'host';
}

export interface ClassifyInput {
  url: string;
  positions: Position[];
  sinks: string[];
  /** Module loaders this URL was passed to as their specifier — see `findCodeLoads`. */
  loaders: string[];
  selfOrigins: SelfOrigin[];
  intel: IntelHit | null;
}

export interface UrlVerdict {
  severity: Severity;
  position: Position;
  provenance: Provenance;
  sinks: string[];
  loaders: string[];
  /** Every rule that contributed, most decisive first — this is what the report shows. */
  reasons: string[];
}

/**
 * First match wins. The order is the policy: the rules that catch a malicious package
 * all sit above the rule that credits a package for pointing at its own repository,
 * because the manifest those origins come from is publisher-controlled. A compromised
 * version of a trusted package cannot clear itself by keeping its real metadata.
 */
export function classifyUrl(input: ClassifyInput): UrlVerdict {
  const { url, sinks, loaders, selfOrigins, intel } = input;
  const position = worstPosition(input.positions);
  const parts = parseUrlParts(url);

  // Unparseable but regex-matched — no host to reason about, so no claim to make.
  if (!parts) {
    return { severity: 'info', position, provenance: 'third-party', sinks, loaders, reasons: ['unparseable URL'] };
  }

  const { provenance, source } = classifyOrigin(parts, selfOrigins);
  const abuse = matchAbuseInfrastructure(parts);
  const rawIp = isRawIpHost(parts.host);
  const loopback = isLoopbackHost(parts.host);
  const inert = INERT_POSITIONS.has(position);
  const reachable = sinks.length > 0;
  // A `script-manual` URL sits in a command, so it is judged like code — but a
  // dependency's own `test` or `lint` script is never run by the person installing
  // it, so its mere presence is not by itself worth a prompt.
  const executable = position === 'code' || position === 'script-manual';

  const verdict = (severity: Severity, ...reasons: string[]): UrlVerdict => ({
    severity,
    position,
    provenance,
    sinks,
    loaders,
    reasons,
  });

  // --- critical: block without asking ---

  if (intel?.confidence === 'exact') return verdict('critical', `${intel.source}: ${intel.detail}`);

  if (position === 'script-hook') {
    return verdict('critical', 'URL inside a lifecycle script that npm runs automatically on install');
  }

  // A remote dynamic dependency. This is strictly worse than the fetch rules below:
  // a fetched URL yields data the package then has to do something with, while a
  // required URL yields code that has already run. Provenance is deliberately not an
  // exemption — a URL on the publisher's own domain is still code that is not in the
  // tarball, not reviewable, and not pinned, so `self` earns no discount here.
  if (loaders.length > 0 && !inert && !loopback) {
    // A fully pinned package-CDN URL is the one honest use of this shape — browser
    // builds that import a published dependency straight from the registry's CDN
    // (yargs' browser shim does exactly this). The code is still off-tarball and
    // still fetched at runtime, so it is worth a decision; it is not worth a block,
    // because the version cannot be swapped after the fact.
    if (isPinnedPackageCdn(parts)) {
      return verdict(
        'warn',
        `remote module loaded via ${loaders.join(', ')}`,
        'version-pinned package CDN — immutable content, but fetched at runtime instead of installed',
      );
    }

    return verdict(
      'critical',
      `remote code loaded and executed via ${loaders.join(', ')}`,
      'the response body runs in-process on import — it is not in the published tarball and can change per download',
    );
  }

  if (abuse && !inert) {
    return verdict('critical', `known exfiltration infrastructure (${abuse})`, `found in ${position}`);
  }

  // Loopback and RFC1918 addresses can't receive data from someone else's machine.
  // They belong to dev servers and doc examples, so they stop here rather than
  // falling into the raw-IP rules below.
  if (loopback) {
    return verdict('info', 'loopback address — not reachable off this machine');
  }

  if (rawIp && executable && reachable && !isPrivateIpHost(parts.host)) {
    return verdict('critical', 'raw IP address contacted directly, bypassing DNS', `reached via ${sinks.join(', ')}`);
  }

  // --- warn: prompt, defaulting to No ---

  if (intel) return verdict('warn', `${intel.source}: ${intel.detail}`);

  if (abuse) {
    return verdict('warn', `known exfiltration infrastructure (${abuse})`, `only in ${position}, not executed`);
  }

  if (reachable && provenance === 'third-party' && executable) {
    return verdict('warn', `third-party URL reached via ${sinks.join(', ')}`);
  }

  // Plaintext matters for somewhere data could actually go. `http://www.w3.org/2000/svg`
  // is an XML namespace identifier and `http://apache.org/licenses/...` is a licence
  // pointer — neither is ever fetched, and both appear in a large share of packages.
  if (parts.scheme === 'http' && executable && provenance === 'third-party') {
    return verdict('warn', 'plaintext http:// in executable code');
  }

  if (isPunycodeHost(parts.host) && provenance !== 'self') {
    return verdict('warn', 'punycode host — may be a homoglyph of a legitimate domain');
  }

  if (executable && rawIp) {
    return verdict('warn', 'raw IP address in code');
  }

  if (executable && hasNonStandardPort(parts)) {
    return verdict('warn', `non-standard port ${parts.port}`);
  }

  if (executable && hasExecutablePath(parts)) {
    return verdict('warn', 'URL points at an executable or archive');
  }

  // --- info: shown, but never changes the verdict ---

  if (provenance === 'self') {
    return verdict('info', `matches the package's own ${source} field`);
  }

  if (provenance === 'ecosystem') {
    return verdict('info', `standards or ecosystem host (${source})`);
  }

  if (inert) {
    return verdict('info', `${position} only — never executed`);
  }

  return verdict('info', 'no sink, no reputation hit');
}

/** Netmasks, broadcast and multicast — addressing constants, not destinations. */
function isNonRoutableLiteral(ip: string): boolean {
  if (ip.startsWith('255.')) return true;
  if (ip === '0.0.0.0' || ip === '::' || ip === '::1') return true;
  const first = Number(ip.split('.')[0]);
  return Number.isInteger(first) && first >= 224 && first <= 239;
}

export interface ClassifyIpInput {
  ip: string;
  positions: Position[];
  sinks: string[];
  loaders: string[];
}

/**
 * The same reasoning applied to bare IP literals. Without this the old
 * "any IP is a finding" behaviour survives, and `255.255.255.0` in a subnet helper
 * keeps costing a package its clean report.
 */
export function classifyIp(input: ClassifyIpInput): UrlVerdict {
  const { ip, sinks, loaders } = input;
  const position = worstPosition(input.positions);
  const reachable = sinks.length > 0;

  const verdict = (severity: Severity, ...reasons: string[]): UrlVerdict => ({
    severity,
    position,
    provenance: 'third-party',
    sinks,
    loaders,
    reasons,
  });

  if (isNonRoutableLiteral(ip)) return verdict('info', 'netmask or non-routable address');
  if (isLoopbackHost(ip)) return verdict('info', 'loopback address — not reachable off this machine');

  if (position === 'script-hook') {
    return verdict('critical', 'IP address inside a lifecycle script that npm runs on install');
  }

  const executable = position === 'code' || position === 'script-manual';

  if (loaders.length > 0 && !INERT_POSITIONS.has(position) && !isPrivateIpHost(ip)) {
    return verdict('critical', `remote code loaded from a raw IP address via ${loaders.join(', ')}`);
  }

  if (isPrivateIpHost(ip)) {
    return reachable && executable
      ? verdict('warn', `private-network address contacted via ${sinks.join(', ')}`)
      : verdict('info', 'private-network address');
  }

  if (executable && reachable) {
    return verdict('critical', 'public IP contacted directly, bypassing DNS', `reached via ${sinks.join(', ')}`);
  }

  if (executable) return verdict('warn', 'public IP literal in executable code');

  return verdict('info', `${position} only — never executed`);
}

export type SeverityCounts = Record<Severity, number>;

export function countBySeverity(severities: Severity[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, warn: 0, info: 0 };
  for (const severity of severities) counts[severity]++;
  return counts;
}
