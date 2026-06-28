"use client";

import { motion } from "motion/react";
import { ArrowRight, Eye, EyeOff, Lock, Sparkles, KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";

const stats = [
  { k: "Privacy model", v: "Mandatory disclosure to one auditor" },
  { k: "Proof system", v: "Groth16 · BN254" },
  { k: "In-circuit ECDH", v: "Baby JubJub + Poseidon2 AEAD" },
  { k: "Status", v: "Live on Stellar testnet" },
];

export function Hero() {
  return (
    <section id="top" className="relative mx-auto max-w-6xl px-5 pb-20 pt-36 md:pt-44">
      <div className="grid items-center gap-12 lg:grid-cols-[1.1fr_0.9fr]">
        <div>
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <span className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3.5 py-1.5 text-xs font-medium text-muted-foreground">
              <Sparkles className="h-3.5 w-3.5 text-veil-violet" />
              Verifiable auditor view key · Soroban
            </span>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.05 }}
            className="mt-6 text-5xl font-black leading-[0.95] tracking-tight md:text-7xl"
          >
            <span className="text-gradient animate-gradient-x">See nothing.</span>
            <br />
            <span className="text-foreground">Audit everything.</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.12 }}
            className="mt-6 max-w-xl text-lg leading-relaxed text-muted-foreground"
          >
            Lumenveil brings <span className="text-foreground">compliant privacy</span> to Stellar.
            The public ledger reveals nothing — yet a designated auditor is{" "}
            <span className="text-foreground">cryptographically guaranteed</span> to recover the true
            amounts, because the disclosure ciphertext is <em>proven correct</em> in zero knowledge.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.18 }}
            className="mt-8 flex flex-wrap items-center gap-3"
          >
            <Button
              variant="glow"
              size="lg"
              onClick={() =>
                document.getElementById("console")?.scrollIntoView({ behavior: "smooth" })
              }
            >
              Open the Auditor Console
              <ArrowRight className="h-4 w-4" />
            </Button>
            <a href="#how">
              <Button variant="outline" size="lg">
                How it works
              </Button>
            </a>
          </motion.div>

          <motion.dl
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.8, delay: 0.3 }}
            className="mt-12 grid max-w-xl grid-cols-2 gap-x-6 gap-y-5"
          >
            {stats.map((s) => (
              <div key={s.k} className="border-l border-white/10 pl-4">
                <dt className="text-[11px] uppercase tracking-wider text-muted-foreground/70">
                  {s.k}
                </dt>
                <dd className="mt-0.5 text-sm font-semibold text-foreground">{s.v}</dd>
              </div>
            ))}
          </motion.dl>
        </div>

        <HeroVisual />
      </div>
    </section>
  );
}

/** A looping "encrypted on the ledger → revealed to the auditor" teaser. */
function HeroVisual() {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.92 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.8, delay: 0.2, ease: "easeOut" }}
      className="relative mx-auto w-full max-w-md"
    >
      <div className="absolute inset-0 -z-10 animate-aurora rounded-[2rem] bg-veil-violet/20 blur-3xl" />

      {/* public ledger view */}
      <div className="glass ring-card rounded-3xl p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
            <EyeOff className="h-4 w-4" /> What the public sees
          </div>
          <span className="rounded-full bg-veil-rose/10 px-2 py-0.5 text-[10px] font-semibold text-veil-rose">
            encrypted
          </span>
        </div>
        <div className="mt-4 space-y-2.5">
          {["commitment", "ephemeral R", "ciphertext"].map((row, i) => (
            <div key={row} className="flex items-center gap-3">
              <span className="w-24 shrink-0 font-mono text-[11px] text-muted-foreground/70">
                {row}
              </span>
              <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-white/[0.05]">
                <motion.div
                  className="h-full rounded-full bg-gradient-to-r from-veil-violet/60 to-veil-cyan/40"
                  animate={{ width: ["30%", "92%", "55%", "80%"] }}
                  transition={{ duration: 6, delay: i * 0.4, repeat: Infinity, ease: "easeInOut" }}
                />
              </div>
              <Lock className="h-3.5 w-3.5 text-muted-foreground/60" />
            </div>
          ))}
        </div>
      </div>

      {/* decrypt key */}
      <motion.div
        animate={{ y: [0, -6, 0] }}
        transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
        className="relative z-10 mx-auto -my-4 flex w-fit items-center gap-2 rounded-full border border-veil-violet/40 bg-background/90 px-4 py-2 text-xs font-semibold text-veil-violet shadow-xl shadow-veil-violet/30"
      >
        <KeyRound className="h-4 w-4" />
        auditor key · S = a·R
      </motion.div>

      {/* auditor view */}
      <div className="glass rounded-3xl p-6 ring-1 ring-veil-emerald/10">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
            <Eye className="h-4 w-4 text-veil-emerald" /> What the auditor recovers
          </div>
          <span className="rounded-full bg-veil-emerald/10 px-2 py-0.5 text-[10px] font-semibold text-veil-emerald">
            verified
          </span>
        </div>
        <div className="mt-4 flex items-end justify-between">
          <div>
            <div className="text-[11px] uppercase tracking-wider text-muted-foreground/70">
              amount
            </div>
            <motion.div
              animate={{ opacity: [0.35, 1], filter: ["blur(6px)", "blur(0px)"] }}
              transition={{ duration: 1.2, repeat: Infinity, repeatType: "reverse", repeatDelay: 2 }}
              className="mt-1 font-mono text-3xl font-bold text-foreground"
            >
              17.00
            </motion.div>
          </div>
          <div className="text-right text-[11px] leading-relaxed text-muted-foreground/70">
            commitment ✓ <br /> re-derived on decrypt
          </div>
        </div>
      </div>
    </motion.div>
  );
}
