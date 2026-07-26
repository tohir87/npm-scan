import prompts from 'prompts';
import type { FindingsReport } from './analyzer.js';

// npm runs these automatically during install — no user invocation needed
const AUTO_RUN_HOOKS = new Set([
  'preinstall', 'install', 'postinstall',
  'prepare', 'prepublish',
  'prepack', 'postpack',
]);

const A = {
  red:    '\x1b[31m',
  yellow: '\x1b[33m',
  green:  '\x1b[32m',
  cyan:   '\x1b[36m',
  bold:   '\x1b[1m',
  dim:    '\x1b[2m',
  reset:  '\x1b[0m',
};

function c(color: keyof typeof A, text: string): string {
  return `${A[color]}${text}${A.reset}`;
}

const MAX_DISPLAY = 20;

export async function presentFindings(report: FindingsReport): Promise<boolean> {
  const { spec, resolvedVersion, filesScanned, urls, ips, scripts } = report;
  const scriptEntries = Object.entries(scripts);
  const autoRunCount = scriptEntries.filter(([name]) => AUTO_RUN_HOOKS.has(name)).length;
  const totalFindings = urls.length + ips.length + autoRunCount;

  console.log('');
  console.log(c('bold', `[npm-scan] Report: ${spec} → ${resolvedVersion}`));
  console.log(c('dim', `  ${filesScanned} file(s) scanned`));
  console.log('');

  // All scripts from package.json
  if (scriptEntries.length > 0) {
    const label = autoRunCount > 0
      ? c('red', `  Scripts (${scriptEntries.length} found, ${autoRunCount} run automatically on install):`)
      : c('yellow', `  Scripts (${scriptEntries.length} found):`);
    console.log(label);
    for (const [name, cmd] of scriptEntries) {
      const isAutoRun = AUTO_RUN_HOOKS.has(name);
      const tag = isAutoRun ? c('red', ' [auto-run]') : c('dim', '           ');
      console.log(`    ${c(isAutoRun ? 'yellow' : 'dim', name.padEnd(16))}${tag}  ${cmd}`);
    }
  } else {
    console.log(c('green', '  Scripts: none'));
  }
  console.log('');

  // Remote URLs
  if (urls.length > 0) {
    const shown = Math.min(urls.length, MAX_DISPLAY);
    console.log(c('yellow', `  Remote URLs (${urls.length} found, showing ${shown}):`));
    for (const f of urls.slice(0, MAX_DISPLAY)) {
      console.log(`    ${c('dim', `${f.file}:${f.line}`)}  ${f.match}`);
    }
    if (urls.length > MAX_DISPLAY) {
      console.log(c('dim', `    ... and ${urls.length - MAX_DISPLAY} more`));
    }
  } else {
    console.log(c('green', '  Remote URLs: none'));
  }
  console.log('');

  // IP addresses
  if (ips.length > 0) {
    const shown = Math.min(ips.length, MAX_DISPLAY);
    console.log(c('red', `  IP addresses (${ips.length} found, showing ${shown}):`));
    for (const f of ips.slice(0, MAX_DISPLAY)) {
      console.log(`    ${c('dim', `${f.file}:${f.line}`)}  ${f.match}`);
    }
    if (ips.length > MAX_DISPLAY) {
      console.log(c('dim', `    ... and ${ips.length - MAX_DISPLAY} more`));
    }
  } else {
    console.log(c('green', '  IP addresses: none'));
  }
  console.log('');

  if (totalFindings === 0) {
    console.log(c('green', '  No suspicious findings.'));
  } else {
    console.log(c('red', `  ${totalFindings} finding(s) — review before proceeding.`));
  }
  console.log('');

  // Remote URLs are an automatic disqualifier — no point asking, just block
  if (urls.length > 0) {
    console.log(c('red', `  Blocked: remote URL(s) found in package contents.`));
    console.log('');
    return false;
  }

  const response = await prompts({
    type: 'confirm',
    name: 'proceed',
    message: `Proceed with installing ${c('bold', spec)}?`,
    // Default to Yes only when nothing suspicious found
    initial: totalFindings === 0,
  });

  // prompts returns {} when user hits Ctrl+C — treat as No
  return response.proceed === true;
}
