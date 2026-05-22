# npm-scan

A local CLI security gateway that wraps `npm install`. Before any package lands on your machine, `npm-scan` fetches the tarball in isolation, scans it for suspicious network callbacks and lifecycle hooks, shows you a report, and only proceeds when you say yes.

## How it works

```
npm-scan install <package>
       │
       ├─ Fetches tarball via pacote (no scripts run)
       ├─ Extracts to a temp directory
       ├─ Scans .js/.ts/.mjs/.cjs/package.json files for:
       │     • HTTP/HTTPS URLs
       │     • Raw IPv4 and IPv6 addresses
       │     • Lifecycle scripts (preinstall, postinstall, prepare…)
       ├─ Shows you the findings
       └─ Asks: proceed? Y/N
              ├─ Yes → runs real npm install, cleans up temp dir
              └─ No  → wipes temp dir, exits cleanly
```

All other `npm` commands (e.g. `npm-scan ls`, `npm-scan run build`) are passed straight through to the native `npm` binary, unchanged.

## Demo

```
$ npm-scan install some-package

[npm-scan] Fetching some-package for inspection...

[npm-scan] Report: some-package → 2.3.1
  6 file(s) scanned

  Lifecycle scripts (1 found — these run on your machine):
    postinstall   node scripts/setup.js

  Remote URLs (3 found, showing 3):
    lib/index.js:14  https://telemetry.example.com/collect
    lib/index.js:89  https://github.com/example/some-package
    package.json:4   https://github.com/example/some-package

  IP addresses: none

  4 finding(s) — review before proceeding.

? Proceed with installing some-package? › (y/N)
```

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
  analyzer.ts   # pacote fetch + file walker + regex scanner
  prompt.ts     # ANSI-coloured report + interactive Y/N prompt
  installer.ts  # Native npm passthrough and final install handover
scripts/
  add-hashbang.mjs  # Post-build: prepends #!/usr/bin/env node
```

## What is and isn't scanned

| Checked | Not checked |
|---------|-------------|
| `.js`, `.ts`, `.mjs`, `.cjs`, `package.json` files | Binary `.node` native addons |
| HTTP/HTTPS URLs in source | Base64/hex-encoded strings |
| Raw IPv4 and IPv6 addresses | Transitive dependencies |
| Lifecycle hooks in root `package.json` | Files > depth of package root |

> `npm-scan` is a first-line review tool, not a sandbox. It catches common patterns used in supply chain attacks (phone-home URLs, raw IP callbacks, surprise install hooks) but does not execute or emulate code.

## Build scripts

```bash
npm run build   # tsc → add hashbang → chmod 755
npm run clean   # rm -rf dist
```

## Tech stack

- **TypeScript** with `module: NodeNext` (full ESM)
- **[pacote](https://github.com/npm/pacote)** — npm's own tarball fetcher, with `ignoreScripts: true`
- **[prompts](https://github.com/terkelg/prompts)** — lightweight interactive CLI prompts

## License

MIT
