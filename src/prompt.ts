import prompts from 'prompts';
import type { FindingsReport } from './analyzer.js';

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
  const { spec, resolvedVersion, filesScanned, urls, ips, lifecycleScripts } = report;
  const hookCount = Object.keys(lifecycleScripts).length;
  const totalFindings = urls.length + ips.length + hookCount;

  console.log('');
  console.log(c('bold', `[npm-scan] Report: ${spec} → ${resolvedVersion}`));
  console.log(c('dim', `  ${filesScanned} file(s) scanned`));
  console.log('');

  // Lifecycle scripts
  if (hookCount > 0) {
    console.log(c('red', `  Lifecycle scripts (${hookCount} found — these run on your machine):`));
    for (const [hook, cmd] of Object.entries(lifecycleScripts)) {
      console.log(`    ${c('yellow', hook.padEnd(12))} ${cmd}`);
    }
  } else {
    console.log(c('green', '  Lifecycle scripts: none'));
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
