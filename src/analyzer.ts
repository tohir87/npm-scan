import pacote from 'pacote';
const { extract, manifest } = pacote;
import { readFile, readdir } from 'fs/promises';
import { join, relative } from 'path';

export interface FindingsReport {
  spec: string;
  resolvedVersion: string;
  filesScanned: number;
  urls: Array<{ file: string; line: number; match: string }>;
  ips: Array<{ file: string; line: number; match: string }>;
  scripts: Record<string, string>;
  autoRunScripts: string[];
}

// npm runs these automatically during install — no user invocation needed
export const AUTO_RUN_HOOKS = new Set([
  'preinstall', 'install', 'postinstall',
  'prepare', 'prepublish',
  'prepack', 'postpack',
]);

const SCANNABLE_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.json']);

// HTTP/HTTPS URLs — stops at whitespace and common string-terminating characters
const URL_PATTERN = /https?:\/\/[^\s'"` <>\\[\](){}]+/g;

// IPv4 — strict per-octet 0-255 range, all 4 octets required
const IPV4_PATTERN = /\b((?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d))\b/g;

// IPv6 — full, compressed (::), and loopback (::1) forms
const IPV6_PATTERN =
  /(?<![.\w])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?![.\w])|(?:[0-9a-fA-F]{1,4}:){1,6}::?(?:[0-9a-fA-F]{1,4})?|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}/g;

function getExt(filename: string): string {
  const dot = filename.lastIndexOf('.');
  return dot >= 0 ? filename.slice(dot) : '';
}

export async function fetchAndScan(spec: string, tempDir: string): Promise<FindingsReport> {
  const pkg = await manifest(spec);
  const resolvedVersion: string = pkg.version;

  await extract(spec, tempDir, { ignoreScripts: true });

  const entries = await readdir(tempDir, { recursive: true, withFileTypes: true });
  const files = entries
    .filter((e) => e.isFile() && SCANNABLE_EXTENSIONS.has(getExt(e.name)))
    // parentPath is Node >=20.12; earlier versions use path
    .map((e) => join((e as NodeDirentCompat).parentPath ?? (e as NodeDirentCompat).path, e.name));

  const urls: FindingsReport['urls'] = [];
  const ips: FindingsReport['ips'] = [];
  const scripts: Record<string, string> = {};

  for (const filePath of files) {
    const relPath = relative(tempDir, filePath);
    let content: string;
    try {
      content = await readFile(filePath, 'utf8');
    } catch {
      continue;
    }

    if (relPath === 'package.json') {
      try {
        const parsed = JSON.parse(content) as { scripts?: Record<string, string> };
        if (parsed.scripts) {
          for (const [name, cmd] of Object.entries(parsed.scripts)) {
            scripts[name] = cmd;
          }
        }
      } catch {
        // skip malformed package.json
      }
    }

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      URL_PATTERN.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = URL_PATTERN.exec(line)) !== null) {
        urls.push({ file: relPath, line: lineNum, match: m[0] });
      }

      IPV4_PATTERN.lastIndex = 0;
      while ((m = IPV4_PATTERN.exec(line)) !== null) {
        ips.push({ file: relPath, line: lineNum, match: m[1] });
      }

      IPV6_PATTERN.lastIndex = 0;
      while ((m = IPV6_PATTERN.exec(line)) !== null) {
        ips.push({ file: relPath, line: lineNum, match: m[0] });
      }
    }
  }

  const autoRunScripts = Object.keys(scripts).filter((name) => AUTO_RUN_HOOKS.has(name));

  return { spec, resolvedVersion, filesScanned: files.length, urls, ips, scripts, autoRunScripts };
}

// Compatibility shim for Dirent.parentPath vs Dirent.path across Node versions
interface NodeDirentCompat {
  parentPath: string;
  path: string;
}
