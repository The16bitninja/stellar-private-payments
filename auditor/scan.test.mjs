// Tests for the auditor scanner's event decoding (the logic this tool owns;
// scValToNative itself is exercised by the SDK).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nativeAuditRecord, decodeAuditDisclosureEvent, EVENT_NAME } from './scan.mjs';
import { nativeToScVal } from '@stellar/stellar-sdk';

test('nativeAuditRecord maps native values to decimal-string record', () => {
  const rec = nativeAuditRecord({
    name: EVENT_NAME,
    commitment: 100n,
    data: {
      ciphertext: [1001n, 1002n, 1003n, 1004n],
      ephemeral_pub_key: { x: 11n, y: 22n },
      ext_context_hash: 0xc0ffeen,
    },
  });

  assert.deepEqual(rec, {
    commitment: '100',
    ephemeral_pub_key: ['11', '22'],
    ciphertext: ['1001', '1002', '1003', '1004'],
    merkle_root: '0',
    auditor_pub_key: ['0', '0'],
    ext_context_hash: '12648430',
  });
});

test('nativeAuditRecord rejects a non-audit event', () => {
  assert.throws(() =>
    nativeAuditRecord({ name: 'something_else', commitment: 1n, data: {} }),
  );
});

test('decodeAuditDisclosureEvent decodes a contract-shaped ScVal event', () => {
  // Reproduce the contract's event ABI with stellar-sdk ScVal builders.
  const u256 = (v) => nativeToScVal(v, { type: 'u256' });
  const event = {
    topic: [
      nativeToScVal(EVENT_NAME, { type: 'symbol' }),
      u256(100n),
    ],
    value: nativeToScVal(
      {
        ciphertext: [u256(1001n), u256(1002n), u256(1003n), u256(1004n)],
        ephemeral_pub_key: { x: u256(11n), y: u256(22n) },
        ext_context_hash: u256(0xc0ffeen),
      },
      {
        type: {
          ciphertext: ['symbol', null],
          ephemeral_pub_key: ['symbol', null],
          ext_context_hash: ['symbol', null],
        },
      },
    ),
  };

  const rec = decodeAuditDisclosureEvent(event);
  assert.equal(rec.commitment, '100');
  assert.deepEqual(rec.ephemeral_pub_key, ['11', '22']);
  assert.deepEqual(rec.ciphertext, ['1001', '1002', '1003', '1004']);
  assert.equal(rec.ext_context_hash, '12648430');
});

test('decodeAuditDisclosureEvent ignores unrelated events', () => {
  const event = {
    topic: [nativeToScVal('new_commitment_event', { type: 'symbol' })],
    value: nativeToScVal(0n, { type: 'u256' }),
  };
  assert.equal(decodeAuditDisclosureEvent(event), null);
});
