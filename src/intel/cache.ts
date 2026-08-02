import { mkdir, readFile, rename, writeFile } from 'fs/promises';
import { join } from 'path';
import { homedir } from 'os';

/**
 * What a feed looked like when it was downloaded. Recording this in every run log is
 * what keeps a dataset sweep reproducible — a verdict that depended on threat intel
 * is only interpretable alongside the snapshot it was drawn from.
 */
export interface Snapshot<T> {
  source: string;
  fetchedAt: string;
  entryCount: number;
  data: T;
}

export function cacheDir(): string {
  const base = process.env.XDG_CACHE_HOME || join(homedir(), '.cache');
  return join(base, 'npm-scan');
}

/** Returns null when the entry is missing, unreadable, malformed, or past its TTL. */
export async function readCache<T>(name: string, maxAgeMs: number): Promise<Snapshot<T> | null> {
  try {
    const raw = await readFile(join(cacheDir(), name), 'utf8');
    const snapshot = JSON.parse(raw) as Snapshot<T>;
    const age = Date.now() - Date.parse(snapshot.fetchedAt);
    if (!Number.isFinite(age) || age > maxAgeMs) return null;
    return snapshot;
  } catch {
    return null;
  }
}

/** Written via a temp file and renamed, so a killed sweep can't leave a half-file behind. */
export async function writeCache<T>(name: string, snapshot: Snapshot<T>): Promise<void> {
  const dir = cacheDir();
  const target = join(dir, name);
  const temp = `${target}.${process.pid}.tmp`;

  try {
    await mkdir(dir, { recursive: true });
    await writeFile(temp, JSON.stringify(snapshot), 'utf8');
    await rename(temp, target);
  } catch {
    // A cold cache costs a download, never a failed scan.
  }
}

/** Resolves to null on timeout, network error, or non-2xx — callers degrade, never throw. */
export async function fetchText(
  url: string,
  timeoutMs: number,
  init?: RequestInit,
): Promise<string | null> {
  try {
    const response = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    if (!response.ok) return null;
    return await response.text();
  } catch {
    return null;
  }
}
