import { hostMatches, normaliseHost, parseUrlParts } from '../origins.js';
import type { IntelHit } from '../classify.js';
import { fetchText, readCache, writeCache, type Snapshot } from './cache.js';

const CACHE_FILE = 'urlhaus.json';
const DEFAULT_TTL_MS = 12 * 60 * 60 * 1000;

/**
 * abuse.ch moved bulk exports behind a free Auth-Key in 2025; the key goes in the
 * path rather than a header. Overridable because the export path has moved before.
 */
function exportUrl(authKey: string): string {
  const template = process.env.URLHAUS_EXPORT_URL;
  if (template) return template.replace('{key}', authKey);
  return `https://urlhaus-api.abuse.ch/v2/files/exports/${authKey}/recent.csv`;
}

/**
 * Hostnames under which many independent users publish, so the host says nothing
 * about any one file served from it. A single malicious upload must not blanket-flag
 * every package that references the host, so these are excluded from host-level
 * matching — an exact URL match still counts.
 *
 * Tenant-per-subdomain platforms (`*.workers.dev`, `*.vercel.app`) do not belong here:
 * the index stores full hostnames and looks them up exactly, so a listed
 * `evil.workers.dev` already fails to match `other.workers.dev`.
 *
 * The last three were found by checking a live feed rather than guessed — a real
 * URLhaus dump lists malware on all of them.
 */
const SHARED_HOSTS = [
  'githubusercontent.com',
  'github.com',
  'gitlab.com',
  'bitbucket.org',
  'npmjs.org',
  'npmjs.com',
  'jsdelivr.net',
  'unpkg.com',
  'cdnjs.cloudflare.com',
  'amazonaws.com',
  'googleapis.com',
  'blob.core.windows.net',
  'firebasestorage.googleapis.com',
  // Consumer file sharing — one hostname, one path segment per user
  'dropbox.com',
  'drive.google.com',
  'docs.google.com',
  'onedrive.live.com',
  '1drv.ms',
  'sharepoint.com',
  'mega.nz',
  'archive.org',
  'sourceforge.net',
  'cdn.discordapp.com',
  'media.discordapp.net',
];

interface UrlhausData {
  urls: string[];
  hosts: string[];
}

export interface IntelSource {
  name: string;
  status: 'ready' | 'unavailable';
  /** Why it isn't usable — surfaced to the user so a silent no-op is impossible. */
  reason: string | null;
  fetchedAt: string | null;
  entryCount: number;
  lookup(url: string): IntelHit | null;
}

export interface IntelOptions {
  offline: boolean;
  refresh: boolean;
  timeoutMs: number;
}

/** Strips the fragment and a trailing slash so two spellings of one URL compare equal. */
function normaliseUrl(url: string): string {
  const parts = parseUrlParts(url);
  if (!parts) return url.toLowerCase();
  const path = parts.path.replace(/\/$/, '');
  return `${parts.scheme}://${parts.host}${path}`;
}

/** Minimal quoted-CSV field splitter — URLhaus quotes every field and escapes none. */
function splitCsvLine(line: string): string[] {
  const fields: string[] = [];
  let current = '';
  let inQuotes = false;

  for (const char of line) {
    if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      fields.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  fields.push(current);
  return fields;
}

/** Columns: id, dateadded, url, url_status, last_online, threat, tags, link, reporter */
function parseExport(csv: string): UrlhausData {
  const urls = new Set<string>();
  const hosts = new Set<string>();

  for (const line of csv.split('\n')) {
    if (line.startsWith('#') || line.trim() === '') continue;
    const fields = splitCsvLine(line);
    const url = fields[2]?.trim();
    if (!url || !url.startsWith('http')) continue;

    urls.add(normaliseUrl(url));
    const parts = parseUrlParts(url);
    if (parts && !SHARED_HOSTS.some((h) => hostMatches(parts.host, h))) hosts.add(parts.host);
  }

  return { urls: [...urls], hosts: [...hosts] };
}

function unavailable(reason: string): IntelSource {
  return { name: 'urlhaus', status: 'unavailable', reason, fetchedAt: null, entryCount: 0, lookup: () => null };
}

function build(snapshot: Snapshot<UrlhausData>): IntelSource {
  const urls = new Set(snapshot.data.urls);
  const hosts = new Set(snapshot.data.hosts);

  return {
    name: 'urlhaus',
    status: 'ready',
    reason: null,
    fetchedAt: snapshot.fetchedAt,
    entryCount: snapshot.entryCount,
    lookup(url) {
      const parts = parseUrlParts(url);
      if (!parts) return null;

      if (urls.has(normaliseUrl(url))) {
        return { source: 'urlhaus', detail: 'exact URL listed as a malware distribution point', confidence: 'exact' };
      }
      if (hosts.has(normaliseHost(parts.host))) {
        return { source: 'urlhaus', detail: `host ${parts.host} distributes malware`, confidence: 'host' };
      }
      return null;
    },
  };
}

/**
 * Offline-first: the feed is downloaded once and answered from disk after that, so a
 * dataset sweep of a thousand packages makes one HTTP request and returns identical
 * verdicts on a rerun. Every failure path degrades to local signals only.
 */
export async function loadUrlhaus(options: IntelOptions): Promise<IntelSource> {
  const cached = await readCache<UrlhausData>(CACHE_FILE, options.refresh ? 0 : DEFAULT_TTL_MS);
  if (cached) return build(cached);

  if (options.offline) return unavailable('offline and no cached feed');

  const authKey = process.env.URLHAUS_AUTH_KEY;
  if (!authKey) return unavailable('URLHAUS_AUTH_KEY not set — get a free key at auth.abuse.ch');

  const csv = await fetchText(exportUrl(authKey), options.timeoutMs);
  if (csv === null) return unavailable('feed download failed');
  if (csv.startsWith('PK')) return unavailable('feed returned a zip archive, expected CSV');

  const data = parseExport(csv);
  if (data.urls.length === 0) return unavailable('feed contained no usable rows — check the Auth-Key');

  const snapshot: Snapshot<UrlhausData> = {
    source: 'urlhaus',
    fetchedAt: new Date().toISOString(),
    entryCount: data.urls.length,
    data,
  };
  await writeCache(CACHE_FILE, snapshot);
  return build(snapshot);
}
