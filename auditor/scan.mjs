// Lumenveil auditor scanner.
//
// Pulls `AuditDisclosureEvent`s emitted by the pool's `disclose` entry point
// from Stellar RPC (`getEvents`), decodes them into the disclosure-record JSON
// the `lumenveil-auditor` Rust tool consumes, and (optionally) runs that tool to
// reconstruct the hidden ledger.
//
// The event ABI (captured from the contract) is:
//   topics: [ Symbol("audit_disclosure_event"), U256(commitment) ]
//   data:   { ciphertext: [U256;4], ephemeral_pub_key: {x:U256,y:U256},
//             ext_context_hash: U256 }
//
// Usage:
//   node scan.mjs [--pool <C...>] [--rpc <url>] [--start <ledger>]
//                 [--secret <dec>] [--out feed.json] [--run]

import { rpc, scValToNative, nativeToScVal, xdr } from '@stellar/stellar-sdk';
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export const EVENT_NAME = 'audit_disclosure_event';

const RPC_URLS = {
  testnet: 'https://soroban-testnet.stellar.org',
  mainnet: 'https://mainnet.sorobanrpc.com',
};

/** Normalize a topic/value entry (xdr.ScVal or base64 string) to xdr.ScVal. */
function toScVal(v) {
  if (typeof v === 'string') return xdr.ScVal.fromXDR(v, 'base64');
  return v;
}

/**
 * Build a disclosure record (decimal-string JSON, the shape the Rust auditor
 * consumes) from already-decoded native values.
 *
 * `merkle_root` and `auditor_pub_key` are not carried by the event — they are
 * proof public inputs used for full verification, not for reconstruction — so
 * they are left as placeholders here. Reconstruction needs only commitment, R,
 * C_aud and the nonce.
 */
export function nativeAuditRecord({ name, commitment, data }) {
  if (name !== EVENT_NAME) {
    throw new Error(`not an ${EVENT_NAME}: ${name}`);
  }
  const dec = (x) => x.toString();
  return {
    commitment: dec(commitment),
    ephemeral_pub_key: [dec(data.ephemeral_pub_key.x), dec(data.ephemeral_pub_key.y)],
    ciphertext: data.ciphertext.map(dec),
    merkle_root: '0',
    auditor_pub_key: ['0', '0'],
    ext_context_hash: dec(data.ext_context_hash),
  };
}

/** Decode one RPC `getEvents` event into a disclosure record (or null). */
export function decodeAuditDisclosureEvent(event) {
  const topics = (event.topic ?? event.topics).map(toScVal);
  const name = scValToNative(topics[0]);
  if (name !== EVENT_NAME) return null;
  const commitment = scValToNative(topics[1]);
  const data = scValToNative(toScVal(event.value ?? event.valueXdr));
  return nativeAuditRecord({ name, commitment, data });
}

/** Scan the pool's events for disclosures starting at `startLedger`. */
export async function scanDisclosures({ rpcUrl, poolId, startLedger, limit = 100 }) {
  const server = new rpc.Server(rpcUrl, { allowHttp: rpcUrl.startsWith('http://') });
  const nameTopic = nativeToScVal(EVENT_NAME, { type: 'symbol' }).toXDR('base64');

  const res = await server.getEvents({
    startLedger,
    filters: [{ type: 'contract', contractIds: [poolId], topics: [[nameTopic, '*']] }],
    limit,
  });

  return (res.events ?? [])
    .map(decodeAuditDisclosureEvent)
    .filter((r) => r !== null);
}

// ---- CLI ----

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--run') args.run = true;
    else if (a.startsWith('--')) {
      args[a.slice(2)] = argv[i + 1];
      i += 1;
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
  const deployments = loadDeployments(here);

  const network = args.network ?? deployments?.network ?? 'testnet';
  const rpcUrl = args.rpc ?? RPC_URLS[network] ?? RPC_URLS.testnet;
  const poolId = args.pool ?? deployments?.pools?.[0]?.poolContractId;
  const startLedger = args.start ? Number(args.start) : deployments?.pools?.[0]?.deploymentLedger;
  const secret = args.secret ?? process.env.AUDITOR_SECRET ?? '0';
  const out = args.out ?? join(here, 'disclosures.json');

  if (!poolId) {
    console.error('error: no pool contract id (--pool or deployments.json)');
    process.exit(2);
  }
  if (!startLedger) {
    console.error('error: no start ledger (--start or deployments.json)');
    process.exit(2);
  }

  console.error(`Scanning ${poolId} on ${network} from ledger ${startLedger}…`);
  const disclosures = await scanDisclosures({ rpcUrl, poolId, startLedger });
  console.error(`Found ${disclosures.length} disclosure(s).`);

  const feed = { auditor_secret: secret, disclosures };
  writeFileSync(out, JSON.stringify(feed, null, 2));
  console.error(`Wrote feed to ${out}`);

  if (args.run) {
    if (secret === '0') console.error('warning: no --secret/AUDITOR_SECRET; reconstruction will fail');
    const bin = join(here, '..', 'target', 'debug', 'lumenveil-auditor');
    const r = spawnSync(bin, [out], { stdio: 'inherit' });
    process.exit(r.status ?? 0);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(`error: ${e.message}`);
    process.exit(2);
  });
}
