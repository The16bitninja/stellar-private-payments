import { rpc, scValToNative, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import type { DisclosureRecord, DisclosuresResponse, ReconResult } from "@/lib/api";
import { CHAIN } from "@/lib/constants";
import { SNAPSHOT_DISCLOSURES, RECONSTRUCTIONS } from "./snapshot";

const EVENT_NAME = "audit_disclosure_event";

// Config (env-overridable, with the live deployment as defaults). Nothing here is
// secret — the auditor key is entered by the user in the UI.
const RPC_URL = process.env.STELLAR_RPC_URL ?? CHAIN.rpcUrl;
const POOL_ID = process.env.STELLAR_POOL_ID ?? CHAIN.pool;
const START_LEDGER = Number(process.env.STELLAR_START_LEDGER ?? CHAIN.startLedger);

type AnyScVal = Parameters<typeof scValToNative>[0];

function toScVal(v: unknown): AnyScVal {
  return (typeof v === "string" ? xdr.ScVal.fromXDR(v, "base64") : v) as AnyScVal;
}

function nativeAuditRecord(
  commitment: unknown,
  data: {
    ephemeral_pub_key: { x: unknown; y: unknown };
    ciphertext: unknown[];
    ext_context_hash: unknown;
  },
): DisclosureRecord {
  const s = (x: unknown) => String(x);
  return {
    commitment: s(commitment),
    ephemeral_pub_key: [s(data.ephemeral_pub_key.x), s(data.ephemeral_pub_key.y)],
    ciphertext: data.ciphertext.map(s) as [string, string, string, string],
    merkle_root: "0",
    auditor_pub_key: ["0", "0"],
    ext_context_hash: s(data.ext_context_hash),
  };
}

function decodeEvent(event: {
  topic?: unknown[];
  topics?: unknown[];
  value?: unknown;
  valueXdr?: unknown;
}): DisclosureRecord | null {
  const topics = (event.topic ?? event.topics ?? []).map(toScVal);
  if (topics.length < 2) return null;
  if (scValToNative(topics[0]) !== EVENT_NAME) return null;
  const commitment = scValToNative(topics[1]);
  const data = scValToNative(toScVal(event.value ?? event.valueXdr));
  return nativeAuditRecord(commitment, data);
}

async function liveScan(): Promise<DisclosureRecord[]> {
  const server = new rpc.Server(RPC_URL);
  const nameTopic = nativeToScVal(EVENT_NAME, { type: "symbol" }).toXDR("base64");
  const res = await server.getEvents({
    startLedger: START_LEDGER,
    filters: [{ type: "contract", contractIds: [POOL_ID], topics: [[nameTopic, "*"]] }],
    limit: 100,
  });
  const events = (res.events ?? []) as Parameters<typeof decodeEvent>[0][];
  return events.map(decodeEvent).filter((r): r is DisclosureRecord => r !== null);
}

/**
 * Disclosures feed. Tries a live Stellar RPC scan of the deployed pool; falls
 * back to the bundled snapshot (so the demo always has real on-chain data, even
 * if RPC is unreachable or events have aged out of retention).
 */
export async function getDisclosures(): Promise<DisclosuresResponse> {
  let disclosures: DisclosureRecord[] = [];
  let source: "live" | "cache" = "live";
  try {
    disclosures = await liveScan();
  } catch {
    disclosures = [];
  }
  if (disclosures.length === 0) {
    disclosures = SNAPSHOT_DISCLOSURES;
    source = "cache";
  }

  return {
    network: CHAIN.network,
    poolId: POOL_ID,
    deployer: CHAIN.deployer,
    registry: CHAIN.registry,
    verifier: CHAIN.verifier,
    startLedger: START_LEDGER,
    source,
    disclosures,
  };
}

/**
 * Reconstruct disclosures for a given auditor secret.
 *
 * The real reconstruction is done by the Rust `lumenveil-auditor` (ECDH +
 * Poseidon2 decrypt + commitment recheck). A serverless host can't run that
 * native binary, so this hosted endpoint replays the auditor's recorded output:
 * the correct auditor key reveals the true note, any other key fails — exactly
 * as the auditor behaves. (Run the binary from the repo for arbitrary keys.)
 */
export function reconstructFeed(secret: string, disclosures: DisclosureRecord[]): ReconResult[] {
  const forKey = RECONSTRUCTIONS[secret.trim()] ?? {};
  return disclosures.map((d) => {
    const note = forKey[d.commitment];
    if (note) {
      return { commitment: d.commitment, ok: true, ...note };
    }
    return {
      commitment: d.commitment,
      ok: false,
      error: "disclosure did not authenticate (wrong key or tampered)",
    };
  });
}
