"use client";

import { useState } from "react";
import { motion } from "motion/react";
import { Copy, Check, ExternalLink, Boxes, ScrollText } from "lucide-react";
import { CHAIN, expertContract, expertTx } from "@/lib/constants";
import { shorten } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { Heading } from "./Gap";

const contracts = [
  { label: "Privacy pool", id: CHAIN.pool, note: "disclose + set_auditor_pubkey" },
  { label: "Public key registry", id: CHAIN.registry, note: "auditor key discovery" },
  { label: "Groth16 verifier", id: CHAIN.verifier, note: "BN254 SNARK verifier" },
];

const txs = [
  { label: "Deploy audit-enabled pool", hash: CHAIN.txs.deploy },
  { label: "Pin auditor key (set_auditor_pubkey)", hash: CHAIN.txs.pin },
  { label: "Emit disclosure (disclose)", hash: CHAIN.txs.disclose },
];

export function OnChain() {
  return (
    <section id="onchain" className="relative mx-auto max-w-6xl px-5 py-24">
      <Heading
        eyebrow="On-chain proof"
        title="Real contracts. Real transactions."
        subtitle="The entire loop ran live on Stellar testnet — deployed, pinned, disclosed, and reconstructed. Everything below is verifiable on the explorer."
      />

      <div className="mt-12 grid gap-5 lg:grid-cols-2">
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-60px" }}
          transition={{ duration: 0.6 }}
        >
          <Card className="h-full p-6">
            <div className="mb-5 flex items-center gap-2 text-sm font-bold">
              <Boxes className="h-4 w-4 text-veil-violet" /> Contracts
            </div>
            <div className="space-y-3">
              {contracts.map((c) => (
                <CopyRow
                  key={c.id}
                  label={c.label}
                  note={c.note}
                  value={c.id}
                  href={expertContract(c.id)}
                />
              ))}
            </div>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 24 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-60px" }}
          transition={{ duration: 0.6, delay: 0.1 }}
        >
          <Card className="h-full p-6">
            <div className="mb-5 flex items-center gap-2 text-sm font-bold">
              <ScrollText className="h-4 w-4 text-veil-cyan" /> Transactions
            </div>
            <div className="space-y-3">
              {txs.map((t) => (
                <CopyRow key={t.hash} label={t.label} value={t.hash} href={expertTx(t.hash)} />
              ))}
            </div>
            <p className="mt-5 border-t border-white/[0.06] pt-4 text-[11px] text-muted-foreground/60">
              Network: Stellar testnet · deployer{" "}
              <span className="font-mono">{shorten(CHAIN.deployer, 6, 6)}</span>
            </p>
          </Card>
        </motion.div>
      </div>
    </section>
  );
}

function CopyRow({
  label,
  note,
  value,
  href,
}: {
  label: string;
  note?: string;
  value: string;
  href: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.015] px-4 py-3">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[13px] font-medium text-foreground">{label}</span>
        <div className="flex items-center gap-1">
          <button
            onClick={() => {
              navigator.clipboard?.writeText(value);
              setCopied(true);
              setTimeout(() => setCopied(false), 1200);
            }}
            className="grid h-7 w-7 cursor-pointer place-items-center rounded-md text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-foreground"
            aria-label="copy"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-veil-emerald" /> : <Copy className="h-3.5 w-3.5" />}
          </button>
          <a
            href={href}
            target="_blank"
            rel="noreferrer"
            className="grid h-7 w-7 place-items-center rounded-md text-muted-foreground transition-colors hover:bg-white/[0.06] hover:text-foreground"
            aria-label="open in explorer"
          >
            <ExternalLink className="h-3.5 w-3.5" />
          </a>
        </div>
      </div>
      <div className="mt-1 font-mono text-[11px] text-muted-foreground">{shorten(value, 16, 12)}</div>
      {note && <div className="mt-0.5 text-[11px] text-muted-foreground/50">{note}</div>}
    </div>
  );
}
