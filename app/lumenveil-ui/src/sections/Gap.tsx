"use client";

import { motion } from "motion/react";
import { TriangleAlert, ShieldCheck, FileLock2, Binary } from "lucide-react";
import { Card } from "@/components/ui/card";

export function Gap() {
  return (
    <section id="gap" className="relative mx-auto max-w-6xl px-5 py-24">
      <Heading
        eyebrow="The gap"
        title="Binding bytes is not proving correctness"
        subtitle="Upstream privacy pools hash the encrypted output into the proof. That stops a recipient from cheating themselves — but a mandatory auditor can still be handed garbage."
      />

      <div className="mt-12 grid gap-5 md:grid-cols-2">
        <GapCard
          delay={0}
          tone="rose"
          icon={<TriangleAlert className="h-5 w-5" />}
          tag="Upstream"
          title="extDataHash binds the bytes"
          points={[
            "The circuit commits to the hash of the encrypted output.",
            "It never proves those bytes decrypt to the committed note.",
            "A sender can bind random bytes as the “auditor copy.”",
            "The transaction still verifies — the regulator is blind.",
          ]}
          footer={
            <span className="inline-flex items-center gap-2">
              <Binary className="h-3.5 w-3.5" /> integrity of bytes, not of meaning
            </span>
          }
        />
        <GapCard
          delay={0.1}
          tone="emerald"
          icon={<ShieldCheck className="h-5 w-5" />}
          tag="Lumenveil"
          title="The ciphertext is proven correct"
          points={[
            "In-circuit ECDH to the auditor's pinned Baby JubJub key.",
            "Poseidon2 authenticated encryption of (amount, blinding, pk).",
            "A Groth16 proof guarantees C_aud decrypts to the real note.",
            "A poisoned ciphertext simply cannot satisfy the circuit.",
          ]}
          footer={
            <span className="inline-flex items-center gap-2">
              <FileLock2 className="h-3.5 w-3.5" /> integrity of meaning, enforced by ZK
            </span>
          }
        />
      </div>

      <motion.p
        initial={{ opacity: 0, y: 16 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.6, delay: 0.2 }}
        className="mx-auto mt-10 max-w-2xl text-center text-sm text-muted-foreground"
      >
        This is the difference between <span className="text-foreground">binding ciphertext bytes</span>{" "}
        and <span className="text-foreground">proving the ciphertext is correct</span> — the core of
        regulator-friendly, compliant privacy.
      </motion.p>
    </section>
  );
}

function GapCard({
  delay,
  tone,
  icon,
  tag,
  title,
  points,
  footer,
}: {
  delay: number;
  tone: "rose" | "emerald";
  icon: React.ReactNode;
  tag: string;
  title: string;
  points: string[];
  footer: React.ReactNode;
}) {
  const accent = tone === "rose" ? "text-veil-rose" : "text-veil-emerald";
  const ring = tone === "rose" ? "ring-veil-rose/15" : "ring-veil-emerald/15";
  const dot = tone === "rose" ? "bg-veil-rose" : "bg-veil-emerald";
  return (
    <motion.div
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-80px" }}
      transition={{ duration: 0.6, delay }}
    >
      <Card className={`h-full p-7 ring-1 ${ring}`}>
        <div className="flex items-center gap-3">
          <div className={`grid h-10 w-10 place-items-center rounded-xl bg-white/[0.04] ${accent}`}>
            {icon}
          </div>
          <div>
            <div className={`text-[11px] font-semibold uppercase tracking-wider ${accent}`}>{tag}</div>
            <h3 className="text-lg font-bold">{title}</h3>
          </div>
        </div>
        <ul className="mt-5 space-y-3">
          {points.map((p) => (
            <li key={p} className="flex gap-3 text-sm text-muted-foreground">
              <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${dot}`} />
              <span>{p}</span>
            </li>
          ))}
        </ul>
        <div className={`mt-6 border-t border-white/[0.06] pt-4 text-xs font-medium ${accent}`}>
          {footer}
        </div>
      </Card>
    </motion.div>
  );
}

export function Heading({
  eyebrow,
  title,
  subtitle,
}: {
  eyebrow: string;
  title: string;
  subtitle?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 18 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.6 }}
      className="mx-auto max-w-2xl text-center"
    >
      <span className="text-xs font-semibold uppercase tracking-[0.2em] text-veil-violet">
        {eyebrow}
      </span>
      <h2 className="mt-3 text-3xl font-bold tracking-tight md:text-4xl">{title}</h2>
      {subtitle && <p className="mt-4 text-muted-foreground">{subtitle}</p>}
    </motion.div>
  );
}
