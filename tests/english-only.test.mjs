import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const excluded = new Set(['.git', 'node_modules', 'artifacts']);
const binaryExtensions = new Set(['.png']);

async function sourceFiles(directory = root) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (excluded.has(entry.name)) continue;
    const target = path.join(directory, entry.name);
    assert.match(entry.name, /^[\x20-\x7e]+$/, 'Project filenames must use ASCII characters.');
    if (entry.isDirectory()) files.push(...await sourceFiles(target));
    else if (entry.isFile() && !binaryExtensions.has(path.extname(entry.name))) files.push(target);
  }
  return files;
}

test('all project text uses ASCII English source characters', async () => {
  const failures = [];
  for (const file of await sourceFiles()) {
    const lines = (await readFile(file, 'utf8')).split(/\r?\n/);
    for (let index = 0; index < lines.length; index++) {
      if (/[^\x00-\x7f]/.test(lines[index])) failures.push(`${path.relative(root, file)}:${index + 1}`);
    }
  }
  assert.deepEqual(failures, [], 'Use English text and ASCII punctuation. Represent Unicode behavior fixtures with ASCII escapes.');
});

test('the extension declares English document and formatting locales', async () => {
  const html = await readFile(path.join(root, 'extension/report.html'), 'utf8');
  const script = await readFile(path.join(root, 'extension/report.js'), 'utf8');
  assert.match(html, /<html\s+lang="en(?:-US)?"/);
  assert.doesNotMatch(script, /zh-CN|zh-TW|ja-JP/);
});
