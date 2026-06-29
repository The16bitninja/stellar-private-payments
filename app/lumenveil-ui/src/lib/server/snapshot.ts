import type { DisclosureRecord } from "@/lib/api";

// A snapshot of the real on-chain disclosure (captured live from the deployed
// pool CBX7… on Stellar testnet). Used as a fallback when the live RPC scan is
// unavailable (e.g., event-retention expiry, or a host without outbound RPC), so
// the demo always has real data to show.
export const SNAPSHOT_DISCLOSURES: DisclosureRecord[] = [
  {
    commitment:
      "9540031368943096744527080580267672673373745734987132695948350990118182674826",
    ephemeral_pub_key: [
      "5495434379985554612158611975914896993448618895136836699300909060318018202627",
      "9491443924367256189782598215807235943523186510952104724809121685390555160868",
    ],
    ciphertext: [
      "888338220902874202387639939993156034511610058340024407527131080715166508631",
      "12933540096760717406743754169026345187231930578112715563211376337809116550486",
      "7533607008453000059848455209647573279538387462896010847805916208844120429158",
      "5091592665851080326844980134020580763094211775349759368441042765485051421434",
    ],
    merkle_root: "0",
    auditor_pub_key: ["0", "0"],
    ext_context_hash: "12648430",
  },
];

// Reconstructions captured from the real Rust auditor (`lumenveil-auditor`).
// Keyed: auditor secret -> note commitment -> recovered note.
//
// On a serverless host (Vercel) the native prover/auditor binary cannot run, so
// this hosted demo replays the auditor's recorded output. Entering the demo
// auditor key reveals the true note; any other key fails authentication —
// exactly as the real auditor behaves. Run `lumenveil-auditor` from the repo to
// reconstruct arbitrary keys/disclosures.
export const RECONSTRUCTIONS: Record<
  string,
  Record<string, { amount: string; blinding: string; public_key: string }>
> = {
  "1234567890123456789": {
    "9540031368943096744527080580267672673373745734987132695948350990118182674826":
      {
        amount: "17",
        blinding: "5151",
        public_key:
          "216215263064672256348637773189420182188919227694317094530167500225972019341",
      },
  },
};
