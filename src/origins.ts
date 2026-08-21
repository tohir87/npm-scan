import hostedGitInfo from 'hosted-git-info';
import type { Manifest } from 'pacote';

export type Provenance = 'self' | 'ecosystem' | 'third-party';

/**
 * A host this package legitimately talks about, derived from its own manifest.
 * `owner` is set only for shared code hosts, where the host alone proves nothing —
 * `github.com/attacker/payload` and `github.com/owner/repo` share a host.
 */
export interface SelfOrigin {
  host: string;
  owner: string | null;
  /** Which manifest field it came from — carried into the report as a reason. */
  field: string;
}

/**
 * Hosts where the first path segment identifies the account. A URL on one of these
 * is self-referential only when that segment matches the package's own owner.
 */
const CODE_HOSTS = [
  'github.com',
  'gist.github.com',
  'raw.githubusercontent.com',
  'codeload.github.com',
  'objects.githubusercontent.com',
  'gitlab.com',
  'bitbucket.org',
  'codeberg.org',
  'git.sr.ht',
  'sourceforge.net',
];

/**
 * Standards bodies, licence texts and ecosystem documentation. These turn up in
 * licence headers and JSON `$schema` keys in a large share of published packages.
 * Membership only downgrades a URL that is already in an inert position — it is
 * never a reason to ignore one in executable code.
 */
const ECOSYSTEM_HOSTS = [
  'schema.org',
  'json-schema.org',
  'w3.org',
  'spdx.org',
  'opensource.org',
  'unlicense.org',
  'creativecommons.org',
  'gnu.org',
  'apache.org',
  'ietf.org',
  'rfc-editor.org',
  'unicode.org',
  'ecma-international.org',
  'tc39.es',
  'nodejs.org',
  'npmjs.com',
  'npmjs.org',
  'registry.npmjs.org',
  'developer.mozilla.org',
  'developers.google.com',
  'typescriptlang.org',
  'babeljs.io',
  'webpack.js.org',
  'eslint.org',
  'rollupjs.org',
  'es5.github.io',
  'caniuse.com',
  'stackoverflow.com',
];

interface AbusePattern {
  host: string;
  /** When set, the path must start with this too — `discord.com` alone is ordinary. */
  pathPrefix?: string;
  label: string;
}

/**
 * The inverse of a whitelist, and the reason a whitelist isn't needed: hosts with
 * no plausible reason to appear in published package code. Short, stable, and
 * matched against how npm stealers actually move data off a machine.
 */
const ABUSE_PATTERNS: AbusePattern[] = [
  // Ephemeral tunnels — a developer's laptop exposed to the internet
  { host: 'ngrok.io', label: 'ngrok tunnel' },
  { host: 'ngrok-free.app', label: 'ngrok tunnel' },
  { host: 'ngrok.app', label: 'ngrok tunnel' },
  { host: 'trycloudflare.com', label: 'cloudflare quick tunnel' },
  { host: 'serveo.net', label: 'serveo tunnel' },
  { host: 'loca.lt', label: 'localtunnel' },
  { host: 'localtunnel.me', label: 'localtunnel' },
  // Out-of-band interaction / canary beacons — exfil confirmation channels
  { host: 'oastify.com', label: 'burp collaborator beacon' },
  { host: 'burpcollaborator.net', label: 'burp collaborator beacon' },
  { host: 'interact.sh', label: 'interactsh beacon' },
  { host: 'oast.fun', label: 'interactsh beacon' },
  { host: 'oast.pro', label: 'interactsh beacon' },
  { host: 'dnslog.cn', label: 'dnslog beacon' },
  { host: 'requestbin.net', label: 'request bin' },
  { host: 'pipedream.net', label: 'request bin' },
  { host: 'webhook.site', label: 'request bin' },
  { host: 'requestcatcher.com', label: 'request bin' },
  // Chat platforms used as drop points
  { host: 'discord.com', pathPrefix: '/api/webhooks', label: 'discord webhook' },
  { host: 'discordapp.com', pathPrefix: '/api/webhooks', label: 'discord webhook' },
  { host: 'api.telegram.org', pathPrefix: '/bot', label: 'telegram bot api' },
  { host: 't.me', label: 'telegram link' },
  // Paste and anonymous file drops — second-stage payload hosting
  { host: 'pastebin.com', pathPrefix: '/raw', label: 'pastebin raw' },
  { host: 'hastebin.com', label: 'paste site' },
  { host: 'ghostbin.co', label: 'paste site' },
  { host: 'paste.ee', label: 'paste site' },
  { host: 'transfer.sh', label: 'anonymous file drop' },
  { host: 'file.io', label: 'anonymous file drop' },
  { host: 'anonfiles.com', label: 'anonymous file drop' },
  { host: 'gofile.io', label: 'anonymous file drop' },
  { host: '0x0.st', label: 'anonymous file drop' },
  { host: 'temp.sh', label: 'anonymous file drop' },
  // Dynamic DNS — cheap, disposable C2 addressing
  { host: 'duckdns.org', label: 'dynamic dns' },
  { host: 'no-ip.org', label: 'dynamic dns' },
  { host: 'no-ip.com', label: 'dynamic dns' },
  { host: 'hopto.org', label: 'dynamic dns' },
  { host: 'ddns.net', label: 'dynamic dns' },
  { host: 'zapto.org', label: 'dynamic dns' },
  { host: 'myftp.biz', label: 'dynamic dns' },
];

/**
 * CDNs that serve the npm registry's own contents. A code load from one of these is
 * still a remote dependency, but it is a different proposition from an arbitrary
 * host: the artefact is a published package, and a fully pinned version cannot be
 * changed under you, because npm refuses to republish a version that already exists.
 *
 * Membership alone proves nothing — `unpkg.com/pkg` and `unpkg.com/pkg@latest`
 * resolve to whatever is newest, so the pin is the half that carries the guarantee.
 */
const PACKAGE_CDNS = [
  'unpkg.com',
  'cdn.jsdelivr.net',
  'esm.sh',
  'esm.run',
  'cdn.skypack.dev',
  'jspm.dev',
  'ga.jspm.io',
  'cdn.esm.sh',
  'npmcdn.com',
];

/** `pkg@1.2.3`, not `pkg@8` or `pkg@latest` — an exact version, optional prerelease. */
const PINNED_VERSION = /@\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:$|[/?#])/;

/**
 * A package-CDN URL pinned to one exact published version. The content behind it is
 * immutable, so the code being off-tarball is a supply-chain and availability
 * concern rather than a live remote-execution channel.
 */
export function isPinnedPackageCdn(parts: UrlParts): boolean {
  if (!PACKAGE_CDNS.some((cdn) => hostMatches(parts.host, cdn))) return false;
  return PINNED_VERSION.test(parts.path);
}

/** Paths that deliver something to run rather than something to read. */
const EXECUTABLE_PATH = /\.(sh|bash|zsh|ps1|bat|cmd|vbs|scr|exe|dll|so|dylib|bin|elf|msi|apk|jar|zip|tar|tgz|gz|7z|rar)$/i;

export interface UrlParts {
  host: string;
  scheme: string;
  port: string;
  path: string;
  /** First path segment — the account name on a code host. */
  firstSegment: string | null;
}

/**
 * `URL` rejects a fair amount of what the scanner legitimately finds (bare hosts,
 * template leftovers), so a failed parse is a normal outcome, not an error.
 */
export function parseUrlParts(url: string): UrlParts | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;

  const segments = parsed.pathname.split('/').filter(Boolean);
  return {
    host: normaliseHost(parsed.hostname),
    scheme: parsed.protocol.replace(':', ''),
    port: parsed.port,
    path: parsed.pathname,
    firstSegment: segments[0] ?? null,
  };
}

/** Lowercase, strip a trailing dot and a leading `www.` so comparisons line up. */
export function normaliseHost(host: string): string {
  const lower = host.toLowerCase().replace(/\.$/, '');
  return lower.startsWith('www.') ? lower.slice(4) : lower;
}

/**
 * Exact host, or a subdomain of it. Deliberately not an eTLD+1 comparison: every
 * pattern here is a concrete host from a manifest or a hardcoded list, so there is
 * no registrable domain to compute and no public-suffix list to ship.
 */
export function hostMatches(host: string, pattern: string): boolean {
  return host === pattern || host.endsWith(`.${pattern}`);
}

function isCodeHost(host: string): boolean {
  return CODE_HOSTS.some((h) => hostMatches(host, h));
}

function addOrigin(origins: SelfOrigin[], raw: unknown, field: string): void {
  if (typeof raw !== 'string' || raw.length === 0) return;

  const parts = parseUrlParts(raw);
  if (parts) {
    // A single-label host ("com") would match far too much — skip it.
    if (!parts.host.includes('.')) return;
    origins.push({
      host: parts.host,
      owner: isCodeHost(parts.host) ? parts.firstSegment : null,
      field,
    });
    return;
  }

  // `git+ssh://`, `git://`, `github:user/repo` and bare `user/repo` shorthands
  const hosted = hostedGitInfo.fromUrl(raw);
  if (hosted?.domain) {
    origins.push({ host: normaliseHost(hosted.domain), owner: hosted.user ?? null, field });
  }
}

/**
 * The set of hosts the package itself declares. This is what replaces a hand-kept
 * repository whitelist — it is computed per package, so it needs no maintenance and
 * covers the whole registry.
 *
 * The manifest is publisher-controlled, so this can only ever be evidence in a
 * package's favour. `classify.ts` applies it after the rules that catch a malicious
 * package pointing at its own genuine repository.
 */
export function deriveSelfOrigins(manifest: Manifest): SelfOrigin[] {
  const origins: SelfOrigin[] = [];
  const repository = manifest.repository as { url?: string } | string | undefined;
  const bugs = manifest.bugs as { url?: string } | string | undefined;
  const author = manifest.author as { url?: string } | string | undefined;
  const dist = manifest.dist as { tarball?: string } | undefined;
  const funding = manifest.funding as { url?: string } | string | Array<{ url?: string }> | undefined;

  addOrigin(origins, typeof repository === 'string' ? repository : repository?.url, 'repository');
  addOrigin(origins, manifest.homepage, 'homepage');
  addOrigin(origins, typeof bugs === 'string' ? bugs : bugs?.url, 'bugs');
  addOrigin(origins, typeof author === 'string' ? undefined : author?.url, 'author');
  addOrigin(origins, dist?.tarball, 'dist.tarball');

  for (const entry of Array.isArray(funding) ? funding : [funding]) {
    addOrigin(origins, typeof entry === 'string' ? entry : entry?.url, 'funding');
  }

  return origins;
}

export interface OriginMatch {
  provenance: Provenance;
  /** The manifest field or list that matched — shown to the user as justification. */
  source: string | null;
}

export function classifyOrigin(parts: UrlParts, selfOrigins: SelfOrigin[]): OriginMatch {
  for (const origin of selfOrigins) {
    if (!hostMatches(parts.host, origin.host)) continue;
    // On a shared code host the account segment has to match too, otherwise a
    // package's own `repository` field would vouch for every repo on github.com.
    if (origin.owner && parts.firstSegment?.toLowerCase() !== origin.owner.toLowerCase()) continue;
    return { provenance: 'self', source: origin.field };
  }

  for (const host of ECOSYSTEM_HOSTS) {
    if (hostMatches(parts.host, host)) return { provenance: 'ecosystem', source: host };
  }

  return { provenance: 'third-party', source: null };
}

/** Returns a human-readable label when the URL points at known abuse infrastructure. */
export function matchAbuseInfrastructure(parts: UrlParts): string | null {
  for (const pattern of ABUSE_PATTERNS) {
    if (!hostMatches(parts.host, pattern.host)) continue;
    if (pattern.pathPrefix && !parts.path.startsWith(pattern.pathPrefix)) continue;
    return pattern.label;
  }
  return null;
}

export function isRawIpHost(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[');
}

/** Dev servers and doc examples. Nothing can be exfiltrated to the victim's own host. */
export function isLoopbackHost(host: string): boolean {
  return (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host === '0.0.0.0' ||
    host === '[::1]' ||
    host === '[::]' ||
    /^127\./.test(host)
  );
}

/** RFC1918 and link-local — reachable inside a network, never from the open internet. */
export function isPrivateIpHost(host: string): boolean {
  const octets = host.split('.').map(Number);
  if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n))) return false;
  const [a, b] = octets;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

export function isPunycodeHost(host: string): boolean {
  return host.split('.').some((label) => label.startsWith('xn--'));
}

export function hasNonStandardPort(parts: UrlParts): boolean {
  return parts.port !== '' && parts.port !== '80' && parts.port !== '443';
}

export function hasExecutablePath(parts: UrlParts): boolean {
  return EXECUTABLE_PATH.test(parts.path);
}
