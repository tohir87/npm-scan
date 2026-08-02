import { fetchText, readCache, writeCache, type Snapshot } from './cache.js';
import type { IntelOptions } from './urlhaus.js';

const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

export interface OsvAdvisory {
  id: string;
  summary: string;
  /**
   * `MAL-` advisories come from the OpenSSF malicious-packages feed — the package
   * itself is the payload, not a dependency with a bug in it.
   */
  malicious: boolean;
}

export interface OsvResult {
  status: 'ready' | 'unavailable';
  reason: string | null;
  checkedAt: string | null;
  advisories: OsvAdvisory[];
}

interface OsvResponse {
  vulns?: Array<{ id?: string; summary?: string; details?: string }>;
}

function cacheKey(name: string, version: string): string {
  return `osv-${`${name}@${version}`.replace(/[^a-zA-Z0-9._@-]/g, '_')}.json`;
}

function toResult(snapshot: Snapshot<OsvAdvisory[]>): OsvResult {
  return { status: 'ready', reason: null, checkedAt: snapshot.fetchedAt, advisories: snapshot.data };
}

/**
 * One keyless request against OSV.dev, which aggregates the OpenSSF malicious-packages
 * feed alongside ordinary advisories. This is the highest-precision signal available
 * for a single HTTP call: a `MAL-` hit means the published artefact is known-bad, with
 * no inference from its contents.
 *
 * Version-pinned answers are stable, so the result is cached and a sweep re-runs offline.
 */
export async function checkOsv(
  name: string,
  version: string,
  options: IntelOptions,
): Promise<OsvResult> {
  const key = cacheKey(name, version);
  const cached = await readCache<OsvAdvisory[]>(key, options.refresh ? 0 : DEFAULT_TTL_MS);
  if (cached) return toResult(cached);

  if (options.offline) {
    return { status: 'unavailable', reason: 'offline and no cached result', checkedAt: null, advisories: [] };
  }

  const body = await fetchText(OSV_QUERY_URL, options.timeoutMs, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ package: { name, ecosystem: 'npm' }, version }),
  });

  if (body === null) {
    return { status: 'unavailable', reason: 'OSV query failed', checkedAt: null, advisories: [] };
  }

  let parsed: OsvResponse;
  try {
    parsed = JSON.parse(body) as OsvResponse;
  } catch {
    return { status: 'unavailable', reason: 'OSV returned malformed JSON', checkedAt: null, advisories: [] };
  }

  const advisories: OsvAdvisory[] = (parsed.vulns ?? [])
    .filter((v): v is { id: string; summary?: string; details?: string } => typeof v.id === 'string')
    .map((v) => ({
      id: v.id,
      summary: v.summary ?? v.details?.split('\n')[0] ?? '',
      malicious: v.id.startsWith('MAL-'),
    }));

  const snapshot: Snapshot<OsvAdvisory[]> = {
    source: 'osv',
    fetchedAt: new Date().toISOString(),
    entryCount: advisories.length,
    data: advisories,
  };
  await writeCache(key, snapshot);
  return toResult(snapshot);
}
