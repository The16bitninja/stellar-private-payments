import { rpc, scValToNative, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import type { DisclosureRecord, DisclosuresResponse, ReconResult } from "@/lib/api";

const EVENT_NAME = "audit_disclosure_event";
const RPC_URL = "https://soroban-testnet.stellar.org";

// When `next dev` runs, cwd is the Next app dir (app/lumenveil-ui).
const repoRoot = () => join(process.cwd(), "..", "..");
const dataDir = () => join(process.cwd(), "data");
const cacheFile = () => join(dataDir(), "disclosures.json");

type AnyScVal = Parameters<typeof scValToNative>[0];

function deployments() {
  return JSON.parse(
    readFileSync(join(repoRoot(), "deployments", "testnet", "deployments.json"), "utf8"),
  );
}

function toScVal(v: unknown): AnyScVal {
  return (typeof v === "string" ? xdr.ScVal.fromXDR(v, "base64") : v) as AnyScVal;
}

function nativeAuditRecord(commitment: unknown, data: {
  ephemeral_pub_key: { x: unknown; y: unknown };
  ciphertext: unknown[];
  ext_context_hash: unknown;
}): DisclosureRecord {
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
  const name = scValToNative(topics[0]);
  if (name !== EVENT_NAME) return null;
  const commitment = scValToNative(topics[1]);
  const data = scValToNative(toScVal(event.value ?? event.valueXdr));
  return nativeAuditRecord(commitment, data);
}

async function scan(poolId: string, startLedger: number): Promise<DisclosureRecord[]> {
  const server = new rpc.Server(RPC_URL);
  const nameTopic = nativeToScVal(EVENT_NAME, { type: "symbol" }).toXDR("base64");
  const res = await server.getEvents({
    startLedger,
    filters: [{ type: "contract", contractIds: [poolId], topics: [[nameTopic, "*"]] }],
    limit: 100,
  });
  const events = (res.events ?? []) as Parameters<typeof decodeEvent>[0][];
  return events.map(decodeEvent).filter((r): r is DisclosureRecord => r !== null);
}

export async function getDisclosures(): Promise<DisclosuresResponse> {
  const d = deployments();
  const pool = d.pools[0];
  const poolId: string = pool.poolContractId;
  const startLedger: number = pool.deploymentLedger;

  let disclosures: DisclosureRecord[] = [];
  let source: "live" | "cache" = "live";

  try {
    disclosures = await scan(poolId, startLedger);
  } catch {
    source = "cache";
  }

  if (disclosures.length > 0) {
    mkdirSync(dataDir(), { recursive: true });
    writeFileSync(cacheFile(), JSON.stringify({ poolId, disclosures }, null, 2));
  } else if (existsSync(cacheFile())) {
    const cached = JSON.parse(readFileSync(cacheFile(), "utf8"));
    if (cached.disclosures?.length) {
      disclosures = cached.disclosures;
      source = "cache";
    }
  }

  return {
    network: d.network,
    poolId,
    deployer: d.deployer,
    registry: d.public_key_registry,
    verifier: d.verifier,
    startLedger,
    source,
    disclosures,
  };
}

export function reconstructFeed(secret: string, disclosures: DisclosureRecord[]): ReconResult[] {
  mkdirSync(dataDir(), { recursive: true });
  const feedFile = join(dataDir(), "feed.json");
  writeFileSync(feedFile, JSON.stringify({ auditor_secret: secret, disclosures }));

  const bin = join(repoRoot(), "target", "debug", "lumenveil-auditor");
  const r = spawnSync(bin, ["--json", feedFile], { encoding: "utf8" });
  if (r.error || r.status === null) {
    throw new Error("auditor binary not runnable (build it: cargo build -p audit)");
  }
  try {
    return JSON.parse(r.stdout) as ReconResult[];
  } catch {
    throw new Error(`could not parse auditor output: ${r.stdout}\n${r.stderr}`);
  }
}
