import { mkdir, writeFile } from 'node:fs/promises';
import { deflateSync } from 'node:zlib';
const dir = new URL('../extension/icons/', import.meta.url);
await mkdir(dir, { recursive: true });
const table = Uint32Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});
function chunk(type, data) {
  const name = Buffer.from(type), length = Buffer.alloc(4), crc = Buffer.alloc(4);
  length.writeUInt32BE(data.length); let value = 0xffffffff;
  for (const byte of Buffer.concat([name, data])) value = table[(value ^ byte) & 255] ^ (value >>> 8);
  crc.writeUInt32BE((value ^ 0xffffffff) >>> 0);
  return Buffer.concat([length, name, data, crc]);
}
function pixel(x, y) {
  const cornerDistance = Math.hypot(Math.max(0, Math.abs(x - .5) - .27), Math.max(0, Math.abs(y - .5) - .27));
  if (cornerDistance > .21) return [0, 0, 0, 0];
  const ring = Math.abs(Math.hypot(x - .435, y - .425) - .19) < .037;
  const px = x - .57, py = y - .56, t = Math.max(0, Math.min(1, (px + py) / .36));
  const handle = Math.hypot(px - t * .18, py - t * .18) < .041;
  return ring || handle ? [218, 239, 160, 255] : [24, 59, 50, 255];
}
for (const size of [16, 48, 128]) {
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    const sum = [0, 0, 0, 0];
    for (let sy = 0; sy < 4; sy++) for (let sx = 0; sx < 4; sx++) {
      const rgba = pixel((x + (sx + .5) / 4) / size, (y + (sy + .5) / 4) / size);
      rgba.forEach((value, index) => { sum[index] += value; });
    }
    sum.forEach((value, index) => { raw[y * (size * 4 + 1) + 1 + x * 4 + index] = Math.round(value / 16); });
  }
  const header = Buffer.alloc(13); header.writeUInt32BE(size, 0); header.writeUInt32BE(size, 4); header[8] = 8; header[9] = 6;
  await writeFile(new URL(`icon-${size}.png`, dir), Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', header), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]));
}
console.log('Built local extension icons.');
