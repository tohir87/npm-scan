import prompts from 'prompts';
import {
  INSTALL_HOOKS,
  PUBLISH_HOOKS,
  countOccurrences,
  type Finding,
  type FindingsReport,
} from './analyzer.js';
import type { Severity } from './classify.js';

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

const SEVERITY_STYLE: Record<Severity, { color: keyof typeof A; label: string }> = {
  critical: { color: 'red', label: 'CRITICAL' },
  warn: { color: 'yellow', label: 'WARN' },
  info: { color: 'dim', label: 'info' },
};

/** "9 found" when nothing repeats, "5 unique of 9 found" when something does. */
function countLabel(findings: Finding[]): string {
  const total = countOccurrences(findings);
  return findings.length === total
    ? `${total} found`
    : `${findings.length} unique of ${total} found`;
}

/**
 * One severity group. Findings carry the rules that fired, so the report explains
 * itself rather than leaving the user to guess why a URL was singled out.
 */
function printGroup(findings: Finding[], severity: Severity): void {
  if (findings.length === 0) return;

  const { color, label } = SEVERITY_STYLE[severity];
  const shown = Math.min(findings.length, MAX_DISPLAY);
  console.log(c(color, `  ${label} (${countLabel(findings)}, showing ${shown}):`));

  for (const finding of findings.slice(0, MAX_DISPLAY)) {
    const [first, ...others] = finding.occurrences;
    const location = `${first.file}:${first.line}`;
    const more = others.length > 0 ? ` (+${others.length} more)` : '';
    console.log(`    ${c(color, finding.match)}`);
    console.log(`      ${c('dim', `${location}${more} · ${first.position}`)}`);
    for (const reason of finding.verdict.reasons) {
      console.log(`      ${c('dim', `↳ ${reason}`)}`);
    }
  }

  if (findings.length > MAX_DISPLAY) {
    console.log(c('dim', `    ... and ${findings.length - MAX_DISPLAY} more`));
  }
  console.log('');
}

export interface PresentOptions {
  /** When false, no question is asked — the install proceeds only on a clean report. */
  interactive: boolean;
}

export async function presentFindings(
  report: FindingsReport,
  options: PresentOptions = { interactive: true },
): Promise<boolean> {
  const { spec, resolvedVersion, filesScanned, urls, ips, scripts, autoRunScripts } = report;
  const scriptEntries = Object.entries(scripts);
  const findings = [...urls, ...ips];
  const { critical, warn, info } = report.severityCounts;

  console.log('');
  console.log(c('bold', `[npm-scan] Report: ${spec} → ${resolvedVersion}`));
  console.log(c('dim', `  ${filesScanned} file(s) scanned`));

  for (const source of report.intelSources) {
    const detail = source.status === 'ready'
      ? `${source.entryCount} entries, fetched ${source.fetchedAt}`
      : `unavailable — ${source.reason}`;
    console.log(c('dim', `  intel/${source.name}: ${detail}`));
  }
  console.log('');

  const maliciousAdvisories = report.osv.advisories.filter((a) => a.malicious);
  if (maliciousAdvisories.length > 0) {
    console.log(c('red', `  CRITICAL — this package is a known-malicious artefact:`));
    for (const advisory of maliciousAdvisories) {
      console.log(`    ${c('red', advisory.id)}  ${advisory.summary}`);
    }
    console.log('');
  }

  // All scripts from package.json, tagged by when npm actually runs them
  if (scriptEntries.length > 0) {
    const label = autoRunScripts.length > 0
      ? c('yellow', `  Scripts (${scriptEntries.length} found, ${autoRunScripts.length} run automatically on install):`)
      : c('dim', `  Scripts (${scriptEntries.length} found, none run on install):`);
    console.log(label);
    for (const [name, cmd] of scriptEntries) {
      const runsOnInstall = INSTALL_HOOKS.has(name);
      const tag = runsOnInstall
        ? c('yellow', ' [runs on install]')
        : PUBLISH_HOOKS.has(name)
          ? c('dim', ' [packaging]      ')
          : c('dim', '                  ');
      console.log(`    ${c(runsOnInstall ? 'yellow' : 'dim', name.padEnd(16))}${tag}  ${cmd}`);
    }
    if (autoRunScripts.length > 0) {
      console.log(c('yellow', `    ↳ ${autoRunScripts.join(', ')} execute arbitrary code before you import anything`));
    }
  } else {
    console.log(c('green', '  Scripts: none'));
  }
  console.log('');

  if (findings.length === 0) {
    console.log(c('green', '  No URLs or IP addresses found.'));
    console.log('');
  } else {
    printGroup(findings.filter((f) => f.verdict.severity === 'critical'), 'critical');
    printGroup(findings.filter((f) => f.verdict.severity === 'warn'), 'warn');
    printGroup(findings.filter((f) => f.verdict.severity === 'info'), 'info');
  }

  if (report.sinks.length > 0) {
    console.log(c('dim', `  Network/exec sinks near findings: ${report.sinks.join(', ')}`));
    console.log('');
  }

  // --- policy ---
  //
  // The old rule blocked on the presence of any URL, which every published package
  // trips via its own `repository` field. Only critical findings block outright now;
  // warnings are the ones worth a human decision, and info never changes the outcome.

  if (critical > 0) {
    console.log(c('red', `  Blocked: ${critical} critical finding(s).`));
    console.log('');
    return false;
  }

  if (warn === 0) {
    console.log(c('green', `  No critical or warning findings${info > 0 ? ` (${info} informational)` : ''}.`));
    console.log('');
    if (!options.interactive) return true;
  } else {
    console.log(c('yellow', `  ${warn} warning(s) — review before proceeding.`));
    console.log('');
    if (!options.interactive) {
      console.log(c('dim', '  Non-interactive: declining (warnings present).'));
      console.log('');
      return false;
    }
  }

  const response = await prompts({
    type: 'confirm',
    name: 'proceed',
    message: `Proceed with installing ${c('bold', spec)}?`,
    // Default to Yes only when nothing needs a decision
    initial: warn === 0,
  });

  // prompts returns {} when user hits Ctrl+C — treat as No
  return response.proceed === true;
}
