import { readFile, readdir, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateRawSync } from 'node:zlib';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const artifactDir = path.join(root, 'artifacts');
await mkdir(artifactDir, { recursive: true });
const table = Uint32Array.from({ length: 256 }, (_, i) => {
  let value = i;
  for (let bit = 0; bit < 8; bit++) value = (value & 1) ? (0xedb88320 ^ (value >>> 1)) : value >>> 1;
  return value >>> 0;
});
function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) value = table[(value ^ byte) & 255] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}
async function list(dir) {
  const result = [];
  for (const entry of await readdir(path.join(root, dir), { withFileTypes: true })) {
    const relative = path.posix.join(dir, entry.name);
    if (entry.isDirectory()) result.push(...await list(relative));
    else if (entry.isFile() && (entry.name === '.env.example' || !entry.name.startsWith('.')) && entry.name !== '.env') result.push(relative);
  }
  return result.sort();
}
async function zip(files, output, prefix = '') {
  const chunks = [], central = []; let offset = 0;
  for (const relative of files) {
    if (/(^|\/)\.env$|\.log$|node_modules|(^|\/)artifacts\//.test(relative)) throw new Error('Refusing to package local secrets or runtime files.');
    const data = await readFile(path.join(root, relative));
    const name = Buffer.from(prefix + relative, 'utf8'), compressed = deflateRawSync(data), crc = crc32(data);
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0); header.writeUInt16LE(20, 4); header.writeUInt16LE(0x800, 6); header.writeUInt16LE(8, 8);
    header.writeUInt16LE(33, 12); header.writeUInt32LE(crc, 14); header.writeUInt32LE(compressed.length, 18); header.writeUInt32LE(data.length, 22); header.writeUInt16LE(name.length, 26);
    chunks.push(header, name, compressed);
    const record = Buffer.alloc(46);
    record.writeUInt32LE(0x02014b50, 0); record.writeUInt16LE(20, 4); record.writeUInt16LE(20, 6); record.writeUInt16LE(0x800, 8); record.writeUInt16LE(8, 10);
    record.writeUInt16LE(33, 14); record.writeUInt32LE(crc, 16); record.writeUInt32LE(compressed.length, 20); record.writeUInt32LE(data.length, 24); record.writeUInt16LE(name.length, 28); record.writeUInt32LE(offset, 42);
    central.push(record, name); offset += header.length + name.length + compressed.length;
  }
  const directory = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  await writeFile(path.join(artifactDir, output), Buffer.concat([...chunks, directory, end]));
  console.log(output + ': ' + files.length + ' files');
}
const extension = await list('extension');
const backend = (await list('backend')).filter(file => file.endsWith('.mjs') || file.endsWith('/.env.example'));
const tests = (await list('tests')).filter(file => file.endsWith('.mjs'));
const scripts = (await list('scripts')).filter(file => file.endsWith('.mjs'));
await zip(extension.map(file => file), 'Link-Lens-extension.zip');
await zip([...extension, ...backend, ...tests, ...scripts, 'package.json', 'README.md', 'Start-Backend.cmd'], 'Link-Lens-browser-kit.zip', 'Link-Lens/');
