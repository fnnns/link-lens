import { isIP } from 'node:net';

// Conservative outbound allow-list. Special-purpose ranges are intentionally
// denied even where an IANA registry contains globally reachable exceptions.
// Sources: https://www.iana.org/assignments/iana-ipv4-special-registry/
//          https://www.iana.org/assignments/iana-ipv6-special-registry/
const DENIED_V4 = [
  [0, 8], [0x0a000000, 8], [0x64400000, 10], [0x7f000000, 8],
  [0xa9fe0000, 16], [0xac100000, 12], [0xc0000000, 24],
  [0xc0000200, 24], [0xc0586300, 24], [0xc0a80000, 16],
  [0xc6120000, 15], [0xc6336400, 24], [0xcb007100, 24],
  [0xe0000000, 4], [0xf0000000, 4]
];

function publicV4(address) {
  const value = address.split('.').reduce((result, octet) => result * 256 + Number(octet), 0);
  return !DENIED_V4.some(([network, bits]) => {
    const size = 2 ** (32 - bits);
    return Math.floor(value / size) === Math.floor(network / size);
  });
}

function ipv6Words(address) {
  let source = address.toLowerCase();
  if (source.includes('.')) {
    const lastColon = source.lastIndexOf(':');
    const octets = source.slice(lastColon + 1).split('.').map(Number);
    source = source.slice(0, lastColon + 1)
      + ((octets[0] << 8) | octets[1]).toString(16) + ':'
      + ((octets[2] << 8) | octets[3]).toString(16);
  }
  const [left, right] = source.split('::');
  const a = left ? left.split(':') : [];
  const b = right ? right.split(':') : [];
  const words = right === undefined ? a : [...a, ...Array(8 - a.length - b.length).fill('0'), ...b];
  return words.map(word => Number.parseInt(word, 16));
}

export function isPublicAddress(value) {
  if (typeof value !== 'string' || !value || /[\s%]/u.test(value)) return false;
  const bracketed = value.startsWith('[') && value.endsWith(']');
  const address = bracketed ? value.slice(1, -1) : value;
  const family = isIP(address);
  if (family === 4) return !bracketed && publicV4(address);
  if (family !== 6) return false;
  const words = ipv6Words(address);
  // Global unicast only: this also excludes mapped/translated IPv4, ULA,
  // loopback, link-local, multicast, discard-only, and future-use ranges.
  if ((words[0] & 0xe000) !== 0x2000) return false;
  if (words[0] === 0x2001 && (words[1] & 0xfe00) === 0) return false;
  if (words[0] === 0x2001 && words[1] === 0x0db8) return false;
  if (words[0] === 0x2002) return false;
  if (words[0] === 0x3fff && (words[1] & 0xf000) === 0) return false;
  return true;
}
