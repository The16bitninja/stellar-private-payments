// Lumenveil disclosure submitter (sender-side transport).
//
// Submits a disclosure record `(commitment, R, C_aud, extContextHash)` to the
// pool's `disclose` entry point on Stellar, so it is emitted as an
// `AuditDisclosureEvent` for the auditor scanner to pick up. The record is
// produced by the `lumenveil-disclose` Rust tool (a real audit proof) or by
// `lumenveil-auditor gen-demo`.
//
// This is the write-side mirror of `scan.mjs`: it encodes the record into the
// contract's argument ScVals and submits the invocation.
//
// Usage:
//   node disclose.mjs <record.json> [--pool <C...>] [--rpc <url>]
//                     [--secret <S...>] [--network testnet]

import {
  rpc,
  nativeToScVal,
  xdr,
  Contract,
  TransactionBuilder,
  Networks,
  Keypair,
  BASE_FEE,
} from '@stellar/stellar-sdk';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const RPC_URLS = {
  testnet: 'https://soroban-testnet.stellar.org',
  mainnet: 'https://mainnet.sorobanrpc.com',
};
const PASSPHRASES = { testnet: Networks.TESTNET, mainnet: Networks.PUBLIC };

const u256 = (s) => nativeToScVal(BigInt(s), { type: 'u256' });

/** Build a struct ScVal (ScMap with symbol keys, kept in sorted key order). */
function structScVal(entries) {
  const mapEntries = entries
    .slice()
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => new xdr.ScMapEntry({ key: nativeToScVal(k, { type: 'symbol' }), val: v }));
  return xdr.ScVal.scvMap(mapEntries);
}

/**
 * Encode a disclosure record into the positional `pool.disclose` arguments:
 *   (commitment: U256, ephemeral_pub_key: {x,y}, ciphertext: [U256;4],
 *    ext_context_hash: U256)
 */
export function buildDiscloseArgs(record) {
  if (record.ciphertext.length !== 4) {
    throw new Error(`ciphertext must have 4 elements, got ${record.ciphertext.length}`);
  }
  const commitment = u256(record.commitment);
  const ephemeral = structScVal([
    ['x', u256(record.ephemeral_pub_key[0])],
    ['y', u256(record.ephemeral_pub_key[1])],
  ]);
  const ciphertext = xdr.ScVal.scvVec(record.ciphertext.map(u256));
  const extContextHash = u256(record.ext_context_hash);
  return [commitment, ephemeral, ciphertext, extContextHash];
}

/** Build, sign, and submit a `pool.disclose` invocation; returns {hash,status}. */
export async function submitDisclosure({
  rpcUrl,
  networkPassphrase,
  poolId,
  senderSecret,
  record,
}) {
  const server = new rpc.Server(rpcUrl, { allowHttp: rpcUrl.startsWith('http://') });
  const keypair = Keypair.fromSecret(senderSecret);
  const source = await server.getAccount(keypair.publicKey());

  const op = new Contract(poolId).call('disclose', ...buildDiscloseArgs(record));
  let tx = new TransactionBuilder(source, { fee: BASE_FEE, networkPassphrase })
    .addOperation(op)
    .setTimeout(60)
    .build();

  tx = await server.prepareTransaction(tx);
  tx.sign(keypair);

  const sent = await server.sendTransaction(tx);
  if (sent.status === 'ERROR') {
    throw new Error(`sendTransaction failed: ${JSON.stringify(sent.errorResult ?? sent)}`);
  }

  let result;
  for (let i = 0; i < 30; i += 1) {
    result = await server.getTransaction(sent.hash);
    if (result.status !== 'NOT_FOUND') break;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return { hash: sent.hash, status: result?.status ?? 'PENDING' };
}

// ---- CLI ----

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a.startsWith('--')) {
      args[a.slice(2)] = argv[i + 1];
      i += 1;
    } else {
      args._.push(a);
    }
  }
  return args;
}

function loadDeployments(here) {
  try {
    const p = join(here, '..', 'deployments', 'testnet', 'deployments.json');
    return JSON.parse(readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

async function main() {
  const here = dirname(fileURLToPath(import.meta.url));
  const args = parseArgs(process.argv.slice(2));
  const recordPath = args._[0];
  if (!recordPath) {
    console.error('usage: node disclose.mjs <record.json> [--pool C..] [--secret S..] [--network testnet]');
    process.exit(2);
  }

  const raw = JSON.parse(readFileSync(recordPath, 'utf8'));
  const record = raw.record ?? raw; // accept producer output {record,..} or a bare record

  const deployments = loadDeployments(here);
  const network = args.network ?? deployments?.network ?? 'testnet';
  const rpcUrl = args.rpc ?? RPC_URLS[network] ?? RPC_URLS.testnet;
  const networkPassphrase = PASSPHRASES[network] ?? Networks.TESTNET;
  const poolId = args.pool ?? deployments?.pools?.[0]?.poolContractId;
  const senderSecret = args.secret ?? process.env.SENDER_SECRET;

  if (!poolId) {
    console.error('error: no pool contract id (--pool or deployments.json)');
    process.exit(2);
  }
  if (!senderSecret) {
    console.error('error: no sender secret (--secret or SENDER_SECRET)');
    process.exit(2);
  }

  console.error(`Submitting disclosure (commitment ${record.commitment}) to ${poolId}…`);
  const { hash, status } = await submitDisclosure({
    rpcUrl,
    networkPassphrase,
    poolId,
    senderSecret,
    record,
  });
  console.error(`tx ${hash} -> ${status}`);
  process.exit(status === 'SUCCESS' ? 0 : 1);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(`error: ${e.message}`);
    process.exit(2);
  });
}
