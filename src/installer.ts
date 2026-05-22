import { spawn } from 'child_process';

export function passthroughToNpm(args: string[]): void {
  const child = spawn('npm', args, { stdio: 'inherit', shell: false });

  child.on('error', (err) => {
    console.error('[npm-scan] Failed to launch npm:', err.message);
    process.exit(1);
  });

  child.on('close', (code) => {
    process.exit(code ?? 1);
  });
}

export function runNpmInstall(args: string[]): void {
  console.log(`\n[npm-scan] Running: npm ${args.join(' ')}\n`);
  passthroughToNpm(args);
}
