"use client";

import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import {
  KeyRound,
  Lock,
  LockOpen,
  RefreshCw,
  ShieldCheck,
  TriangleAlert,
  Radio,
  Loader2,
} from "lucide-react";
import {
  fetchDisclosures,
  reconstruct,
  type DisclosureRecord,
  type DisclosuresResponse,
  type ReconResult,
} from "@/lib/api";
import { CHAIN, expertContract } from "@/lib/constants";
import { shorten } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Heading } from "./Gap";

export function AuditorConsole() {
  const [data, setData] = useState<DisclosuresResponse | null>(null);
  const [scanning, setScanning] = useState(true);
  const [scanError, setScanError] = useState<string | null>(null);

  const [secret, setSecret] = useState<string>(CHAIN.demoSecret);
  const [results, setResults] = useState<Record<string, ReconResult> | null>(null);
  const [revealing, setRevealing] = useState(false);
  const [revealError, setRevealError] = useState<string | null>(null);

  async function scan() {
    setScanning(true);
    setScanError(null);
    setResults(null);
    try {
      setData(await fetchDisclosures());
    } catch (e) {
      setScanError(e instanceof Error ? e.message : String(e));
    } finally {
      setScanning(false);
    }
  }

  async function reveal() {
    if (!data) return;
    setRevealing(true);
    setRevealError(null);
    try {
      const res = await reconstruct(secret, data.disclosures);
      const map: Record<string, ReconResult> = {};
      for (const r of res) map[r.commitment] = r;
      setResults(map);
    } catch (e) {
      setRevealError(e instanceof Error ? e.message : String(e));
    } finally {
      setRevealing(false);
    }
  }

  useEffect(() => {
    void scan();
  }, []);

  const disclosures = data?.disclosures ?? [];

  return (
    <section id="console" className="relative mx-auto max-w-6xl px-5 py-24">
      <Heading
        eyebrow="Live auditor console"
        title="Recover the hidden ledger, on real testnet data"
        subtitle="These disclosures were emitted by the deployed pool. The public sees only ciphertext — paste the auditor key and watch the true amounts resolve, reconstructed by the real Rust auditor."
      />

      <motion.div
        initial={{ opacity: 0, y: 24 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-60px" }}
        transition={{ duration: 0.6 }}
        className="mx-auto mt-12 max-w-4xl"
      >
        <Card className="overflow-hidden">
          {/* toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] px-6 py-4">
            <div className="flex items-center gap-2.5">
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-veil-cyan/10 text-veil-cyan">
                <Radio className="h-4.5 w-4.5" />
              </span>
              <div>
                <div className="text-sm font-bold">Pool event feed</div>
                <a
                  href={expertContract(CHAIN.pool)}
                  target="_blank"
                  rel="noreferrer"
                  className="font-mono text-[11px] text-muted-foreground hover:text-veil-cyan"
                >
                  {shorten(CHAIN.pool, 10, 8)} ↗
                </a>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {data && (
                <span
                  className={`rounded-full px-2.5 py-1 text-[11px] font-semibold ${
                    data.source === "live"
                      ? "bg-veil-emerald/10 text-veil-emerald"
                      : "bg-veil-amber/10 text-veil-amber"
                  }`}
                >
                  {data.source === "live" ? "live RPC" : "cached"}
                </span>
              )}
              <Button variant="outline" size="sm" onClick={scan} disabled={scanning}>
                <RefreshCw className={`h-3.5 w-3.5 ${scanning ? "animate-spin" : ""}`} />
                Scan
              </Button>
            </div>
          </div>

          {/* ledger */}
          <div className="px-3 py-3 sm:px-6">
            {scanning && !data && <SkeletonRows />}
            {scanError && <ErrorRow text={scanError} />}
            {!scanning && disclosures.length === 0 && !scanError && (
              <div className="py-10 text-center text-sm text-muted-foreground">
                No disclosures found in the scan window.
              </div>
            )}

            <div className="space-y-2.5">
              {disclosures.map((d, i) => (
                <LedgerRow key={d.commitment} index={i} record={d} result={results?.[d.commitment]} />
              ))}
            </div>
          </div>

          {/* auditor key panel */}
          <div className="border-t border-white/[0.06] bg-white/[0.015] px-6 py-5">
            <label className="mb-2 flex items-center gap-2 text-xs font-medium text-muted-foreground">
              <KeyRound className="h-3.5 w-3.5 text-veil-violet" />
              Auditor Baby JubJub secret key
            </label>
            <div className="flex flex-col gap-3 sm:flex-row">
              <input
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                spellCheck={false}
                className="min-w-0 flex-1 rounded-lg border border-white/10 bg-background/60 px-3.5 py-2.5 font-mono text-sm text-foreground outline-none transition-colors focus:border-veil-violet/50 focus:ring-2 focus:ring-veil-violet/20"
                placeholder="auditor secret (decimal)"
              />
              <Button
                variant="glow"
                onClick={reveal}
                disabled={revealing || scanning || disclosures.length === 0}
                className="shrink-0"
              >
                {revealing ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <LockOpen className="h-4 w-4" />
                )}
                {revealing ? "Reconstructing…" : "Decrypt & reconstruct"}
              </Button>
            </div>
            {revealError && (
              <p className="mt-3 flex items-center gap-2 text-xs text-veil-rose">
                <TriangleAlert className="h-3.5 w-3.5" /> {revealError}
              </p>
            )}
            <p className="mt-3 font-mono text-[11px] text-muted-foreground/60">
              auditor computes S = a·R · decrypts C_aud · re-derives commitment
            </p>
          </div>
        </Card>
      </motion.div>
    </section>
  );
}

function LedgerRow({
  index,
  record,
  result,
}: {
  index: number;
  record: DisclosureRecord;
  result?: ReconResult;
}) {
  const revealed = result?.ok;
  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05 }}
      className="grid grid-cols-[1fr_auto] items-center gap-4 rounded-xl border border-white/[0.06] bg-white/[0.015] px-4 py-3"
    >
      <div className="min-w-0">
        <div className="flex items-center gap-2 text-[11px] uppercase tracking-wider text-muted-foreground/60">
          commitment
        </div>
        <div className="truncate font-mono text-[13px] text-foreground">{shorten(record.commitment, 14, 10)}</div>
        <div className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 font-mono text-[10px] text-muted-foreground/50">
          <span>R.x {shorten(record.ephemeral_pub_key[0], 6, 4)}</span>
          <span>c₀ {shorten(record.ciphertext[0], 6, 4)}</span>
          <span>tag {shorten(record.ciphertext[3], 6, 4)}</span>
        </div>
      </div>

      <div className="text-right">
        <AnimatePresence mode="wait" initial={false}>
          {revealed ? (
            <motion.div
              key="revealed"
              initial={{ opacity: 0, filter: "blur(8px)", y: 4 }}
              animate={{ opacity: 1, filter: "blur(0px)", y: 0 }}
              transition={{ duration: 0.5 }}
              className="flex flex-col items-end"
            >
              <div className="flex items-center gap-1.5 font-mono text-xl font-bold text-foreground">
                {result?.amount}
                <span className="text-xs font-normal text-muted-foreground">XLM</span>
              </div>
              <span className="mt-0.5 inline-flex items-center gap-1 text-[10px] font-semibold text-veil-emerald">
                <ShieldCheck className="h-3 w-3" /> commitment verified
              </span>
            </motion.div>
          ) : result && !result.ok ? (
            <motion.div key="failed" className="flex items-center gap-1.5 text-xs text-veil-rose">
              <TriangleAlert className="h-3.5 w-3.5" /> wrong key
            </motion.div>
          ) : (
            <motion.div
              key="locked"
              exit={{ opacity: 0, filter: "blur(8px)" }}
              className="flex flex-col items-end"
            >
              <div className="flex items-center gap-2 text-muted-foreground/50">
                <Lock className="h-3.5 w-3.5" />
                <span className="font-mono text-lg tracking-widest">••••••</span>
              </div>
              <span className="mt-0.5 text-[10px] text-muted-foreground/40">amount hidden</span>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}

function SkeletonRows() {
  return (
    <div className="space-y-2.5">
      {[0, 1].map((i) => (
        <div
          key={i}
          className="h-16 animate-pulse rounded-xl border border-white/[0.06] bg-white/[0.02]"
        />
      ))}
    </div>
  );
}

function ErrorRow({ text }: { text: string }) {
  return (
    <div className="flex items-center gap-2 rounded-xl border border-veil-rose/20 bg-veil-rose/5 px-4 py-3 text-sm text-veil-rose">
      <TriangleAlert className="h-4 w-4 shrink-0" /> {text}
    </div>
  );
}
