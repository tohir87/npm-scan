import { readFile, writeFile } from 'fs/promises';

const file = process.argv[2];
if (!file) {
  console.error('Usage: node scripts/add-hashbang.mjs <file>');
  process.exit(1);
}

const content = await readFile(file, 'utf8');
if (!content.startsWith('#!/usr/bin/env node')) {
  await writeFile(file, '#!/usr/bin/env node\n' + content, 'utf8');
  console.log(`Hashbang added to ${file}`);
}
