export type DisclosureRecord = {
  commitment: string;
  ephemeral_pub_key: [string, string];
  ciphertext: [string, string, string, string];
  merkle_root: string;
  auditor_pub_key: [string, string];
  ext_context_hash: string;
};

export type DisclosuresResponse = {
  network: string;
  poolId: string;
  deployer: string;
  registry: string;
  verifier: string;
  startLedger: number;
  source: "live" | "cache";
  disclosures: DisclosureRecord[];
};

export type ReconResult = {
  commitment: string;
  ok: boolean;
  amount?: string;
  blinding?: string;
  public_key?: string;
  error?: string;
};

export async function fetchDisclosures(): Promise<DisclosuresResponse> {
  const r = await fetch("/api/disclosures", { cache: "no-store" });
  if (!r.ok) throw new Error(`scan failed (${r.status})`);
  return r.json();
}

export async function reconstruct(
  secret: string,
  disclosures: DisclosureRecord[],
): Promise<ReconResult[]> {
  const r = await fetch("/api/reconstruct", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ secret, disclosures }),
  });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || `reconstruct failed (${r.status})`);
  return j.results as ReconResult[];
}
