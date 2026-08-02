import { readFileSync } from 'fs';
import { join } from 'path';

/**
 * Loads `.env` from the working directory so `URLHAUS_AUTH_KEY` lives in one
 * gitignored file rather than in every shell that runs a sweep.
 *
 * Hand-parsed rather than using `process.loadEnvFile()`, which only exists from
 * Node 22.9 — this package supports 18.17, and a dotenv dependency isn't worth it
 * for one key. Real environment variables always win, so `--env`-style overrides and
 * CI secrets keep working.
 */
export function loadDotEnv(dir: string = process.cwd()): void {
  let contents: string;
  try {
    contents = readFileSync(join(dir, '.env'), 'utf8');
  } catch {
    return; // No .env is the normal case, not an error.
  }

  for (const line of contents.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;

    const separator = trimmed.indexOf('=');
    if (separator <= 0) continue;

    const key = trimmed.slice(0, separator).trim();
    if (key in process.env) continue;

    // Strip one layer of matching quotes, so `KEY="value"` yields `value`.
    const raw = trimmed.slice(separator + 1).trim();
    const quoted = raw.length >= 2 && (raw[0] === '"' || raw[0] === "'") && raw.at(-1) === raw[0];
    process.env[key] = quoted ? raw.slice(1, -1) : raw;
  }
}
