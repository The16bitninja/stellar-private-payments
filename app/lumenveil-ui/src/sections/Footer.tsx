import { ShieldCheck, TriangleAlert } from "lucide-react";

const stack = [
  "Circom 2",
  "Groth16 · arkworks",
  "Baby JubJub",
  "Poseidon2",
  "Soroban / Rust",
  "Stellar testnet",
];

export function Footer() {
  return (
    <footer className="relative mx-auto max-w-6xl px-5 pb-16 pt-8">
      <div className="glass ring-card overflow-hidden rounded-3xl p-8 md:p-10">
        <div className="flex flex-col items-start justify-between gap-8 md:flex-row md:items-center">
          <div className="max-w-md">
            <div className="flex items-center gap-2.5">
              <div className="grid h-9 w-9 place-items-center rounded-lg bg-gradient-to-br from-veil-violet to-veil-cyan">
                <ShieldCheck className="h-5 w-5 text-white" strokeWidth={2.5} />
              </div>
              <span className="text-lg font-bold tracking-tight">Lumenveil</span>
            </div>
            <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
              Verifiable auditor disclosure for compliant privacy on Stellar — a deliberately
              regulator-friendly trust model: unconditional privacy from the public, mandatory
              transparency to one designated auditor.
            </p>
          </div>

          <div className="flex flex-wrap gap-2 md:max-w-xs md:justify-end">
            {stack.map((s) => (
              <span
                key={s}
                className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 font-mono text-[11px] text-muted-foreground"
              >
                {s}
              </span>
            ))}
          </div>
        </div>

        <div className="mt-8 flex items-start gap-2 rounded-xl border border-veil-amber/20 bg-veil-amber/5 px-4 py-3 text-[12px] leading-relaxed text-veil-amber/90">
          <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            Research prototype, unaudited — testnet only. Groth16 needs a trusted setup; this is a
            single-contributor hackathon setup, not a ceremony. The auditor key must be
            contract-pinned (it is) or the channel can be poisoned.
          </span>
        </div>

        <div className="mt-6 text-center text-[11px] text-muted-foreground/50">
          Built on Nethermind&apos;s stellar-private-payments · Lumenveil adds the verifiable auditor
          view key.
        </div>
      </div>
    </footer>
  );
}
