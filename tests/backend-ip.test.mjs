import test from 'node:test';
import assert from 'node:assert/strict';
import { isPublicAddress } from '../backend/ip.mjs';

test('public IPv4 addresses and adjacent public boundaries are accepted', () => {
  for (const value of ['1.1.1.1', '8.8.8.8', '93.184.216.34', '100.63.255.255',
    '100.128.0.0', '172.15.255.255', '172.32.0.0', '192.0.1.1', '192.0.3.1',
    '192.88.98.255', '192.88.100.0', '198.17.255.255', '198.20.0.0', '223.255.255.255']) {
    assert.equal(isPublicAddress(value), true, value);
  }
});

test('IPv4 special-purpose, internal, documentation, and multicast ranges are denied', () => {
  for (const value of ['0.0.0.0', '0.255.255.255', '10.0.0.1', '10.255.255.255',
    '100.64.0.0', '100.127.255.255', '127.0.0.1', '127.255.255.255',
    '169.254.169.254', '172.16.0.0', '172.31.255.255', '192.0.0.9',
    '192.0.2.15', '192.88.99.1', '192.168.1.1', '198.18.0.1',
    '198.19.255.255', '198.51.100.1', '203.0.113.1', '224.0.0.1',
    '239.255.255.255', '240.0.0.0', '255.255.255.255']) {
    assert.equal(isPublicAddress(value), false, value);
  }
});

test('global IPv6 forms, compression, uppercase and optional brackets are handled', () => {
  for (const value of ['2001:4860:4860::8888', '2606:4700:4700::1111',
    '2001:0200::1', '2001:db7:ffff::1', '2001:db9::1', '2003::1',
    '3ffe:ffff::1', '3fff:1000::1', '2A00:1450:4001:82B::200E',
    '[2606:4700:4700::1111]', '2001:4860:1:2:3:4:5:6',
    '2001:4860::1.2.3.4']) {
    assert.equal(isPublicAddress(value), true, value);
  }
});

test('IPv6 private/special forms and translation mechanisms are denied', () => {
  for (const value of ['::', '::1', '::ffff:127.0.0.1', '::ffff:8.8.8.8',
    '0:0:0:0:0:ffff:0808:0808', '64:ff9b::a00:1', '64:ff9b:1::1',
    '100::1', '100:0:0:1::1', '2001::1', '2001:1::1', '2001:1ff:ffff::1',
    '2001:db8::1', '2002:0808:0808::1', '3fff::1', '3fff:fff:ffff::1',
    '4000::1', '5f00::1', 'fc00::1', 'fd00::1', 'fe80::1', 'ff02::1']) {
    assert.equal(isPublicAddress(value), false, value);
  }
});

test('invalid, ambiguous, and zone-qualified strings are denied', () => {
  for (const value of [undefined, null, 123, {}, '', 'example.com', '8.8.8.8 ',
    ' 8.8.8.8', '127.1', '2130706433', '0x7f000001', '008.008.008.008',
    '999.1.1.1', '[8.8.8.8]', 'fe80::1%lo0', '[fe80::1%3]',
    '2001:4860::1::2', '[2001:4860::1', '2001:4860::1]',
    '2001:4860::1\n', '2001:4860:0:0:0:0:0:0:1']) {
    assert.equal(isPublicAddress(value), false, String(value));
  }
});
