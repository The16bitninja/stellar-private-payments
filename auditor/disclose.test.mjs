// Tests for the disclosure submitter's argument encoding (the logic this tool
// owns; signing/submission are exercised live).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildDiscloseArgs } from './disclose.mjs';
import { scValToNative } from '@stellar/stellar-sdk';

const RECORD = {
  commitment: '100',
  ephemeral_pub_key: ['11', '22'],
  ciphertext: ['1001', '1002', '1003', '1004'],
  merkle_root: '0',
  auditor_pub_key: ['0', '0'],
  ext_context_hash: '12648430',
};

test('buildDiscloseArgs encodes pool.disclose arguments in order', () => {
  const [commitment, ephemeral, ciphertext, nonce] = buildDiscloseArgs(RECORD);

  assert.equal(scValToNative(commitment).toString(), '100');

  const eph = scValToNative(ephemeral);
  assert.equal(eph.x.toString(), '11');
  assert.equal(eph.y.toString(), '22');

  assert.deepEqual(scValToNative(ciphertext).map(String), ['1001', '1002', '1003', '1004']);

  assert.equal(scValToNative(nonce).toString(), '12648430');
});

test('buildDiscloseArgs round-trips through decodeAuditDisclosureEvent shape', async () => {
  // The args the submitter builds should decode back to the same field values
  // the scanner would read off the event.
  const { nativeAuditRecord } = await import('./scan.mjs');
  const [commitment, ephemeral, ciphertext, nonce] = buildDiscloseArgs(RECORD);
  const rebuilt = nativeAuditRecord({
    name: 'audit_disclosure_event',
    commitment: scValToNative(commitment),
    data: {
      ciphertext: scValToNative(ciphertext),
      ephemeral_pub_key: scValToNative(ephemeral),
      ext_context_hash: scValToNative(nonce),
    },
  });
  assert.equal(rebuilt.commitment, RECORD.commitment);
  assert.deepEqual(rebuilt.ephemeral_pub_key, RECORD.ephemeral_pub_key);
  assert.deepEqual(rebuilt.ciphertext, RECORD.ciphertext);
  assert.equal(rebuilt.ext_context_hash, RECORD.ext_context_hash);
});

test('buildDiscloseArgs rejects a malformed ciphertext', () => {
  assert.throws(() => buildDiscloseArgs({ ...RECORD, ciphertext: ['1', '2', '3'] }));
});
