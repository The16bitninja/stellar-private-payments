"use client";

import { motion } from "motion/react";
import { Cpu, CircuitBoard, Radio, SatelliteDish, Unlock, ArrowRight } from "lucide-react";
import { Heading } from "./Gap";

const steps = [
  {
    icon: Cpu,
    title: "Sender proves",
    body: "Builds the audit witness for an owned note and runs the Groth16 prover (lumenveil-disclose).",
    iconCls: "bg-veil-violet/10 text-veil-violet",
  },
  {
    icon: CircuitBoard,
    title: "Circuit binds",
    body: "selectiveDisclosureAudit recomputes the commitment, does in-circuit ECDH, and encrypts to the auditor.",
    iconCls: "bg-veil-indigo/10 text-veil-indigo",
  },
  {
    icon: Radio,
    title: "Pool emits",
    body: "pool.disclose publishes (commitment, R, C_aud, nonce) as an on-chain AuditDisclosureEvent.",
    iconCls: "bg-veil-cyan/10 text-veil-cyan",
  },
  {
    icon: SatelliteDish,
    title: "Auditor scans",
    body: "scan.mjs pulls the event from Stellar RPC — the only feed the auditor needs.",
    iconCls: "bg-veil-amber/10 text-veil-amber",
  },
  {
    icon: Unlock,
    title: "Truth recovered",
    body: "With S = a·R the auditor decrypts C_aud and re-derives the commitment. Garbage can't pass.",
    iconCls: "bg-veil-emerald/10 text-veil-emerald",
  },
];

export function Pipeline() {
  return (
    <section id="how" className="relative mx-auto max-w-6xl px-5 py-24">
      <Heading
        eyebrow="How it works"
        title="One verifiable path, end to end"
        subtitle="From a private note to a regulator who can read it — every hop is either public-by-design or proven in zero knowledge."
      />

      <div className="mt-14 grid gap-4 md:grid-cols-5">
        {steps.map((s, i) => (
          <motion.div
            key={s.title}
            initial={{ opacity: 0, y: 26 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-60px" }}
            transition={{ duration: 0.5, delay: i * 0.12 }}
            className="relative"
          >
            <div className="glass ring-card h-full rounded-2xl p-5">
              <div className="flex items-center justify-between">
                <div className={`grid h-11 w-11 place-items-center rounded-xl ${s.iconCls}`}>
                  <s.icon className="h-5 w-5" />
                </div>
                <span className="font-mono text-xs text-muted-foreground/50">
                  0{i + 1}
                </span>
              </div>
              <h3 className="mt-4 text-[15px] font-bold">{s.title}</h3>
              <p className="mt-1.5 text-[13px] leading-relaxed text-muted-foreground">{s.body}</p>
            </div>

            {i < steps.length - 1 && (
              <div className="absolute -right-3 top-1/2 z-10 hidden -translate-y-1/2 md:block">
                <motion.div
                  animate={{ x: [0, 4, 0], opacity: [0.4, 1, 0.4] }}
                  transition={{ duration: 1.8, repeat: Infinity, delay: i * 0.2 }}
                  className="grid h-6 w-6 place-items-center rounded-full border border-white/10 bg-background text-muted-foreground"
                >
                  <ArrowRight className="h-3.5 w-3.5" />
                </motion.div>
              </div>
            )}
          </motion.div>
        ))}
      </div>

      <div className="mt-8 flex flex-wrap justify-center gap-2 text-[11px]">
        {["Groth16 · BN254", "Baby JubJub ECDH", "Poseidon2 AEAD", "Soroban event feed", "Route 2 · off consensus path"].map(
          (t) => (
            <span
              key={t}
              className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 font-mono text-muted-foreground"
            >
              {t}
            </span>
          ),
        )}
      </div>
    </section>
  );
}
