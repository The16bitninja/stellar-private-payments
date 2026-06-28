"use client";

import { motion } from "motion/react";
import { ShieldCheck } from "lucide-react";

const links = [
  { href: "#gap", label: "The gap" },
  { href: "#how", label: "How it works" },
  { href: "#console", label: "Auditor console" },
  { href: "#onchain", label: "On-chain" },
];

export function Nav() {
  return (
    <motion.header
      initial={{ y: -24, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.6, ease: "easeOut" }}
      className="fixed inset-x-0 top-0 z-50 flex justify-center px-4 pt-4"
    >
      <nav className="glass flex w-full max-w-5xl items-center justify-between rounded-full py-2.5 pl-5 pr-3">
        <a href="#top" className="flex items-center gap-2.5">
          <div className="grid h-8 w-8 place-items-center rounded-lg bg-gradient-to-br from-veil-violet to-veil-cyan shadow-lg shadow-veil-violet/40">
            <ShieldCheck className="h-[18px] w-[18px] text-white" strokeWidth={2.5} />
          </div>
          <span className="text-[15px] font-bold tracking-tight">Lumenveil</span>
        </a>
        <div className="hidden items-center gap-1 md:flex">
          {links.map((l) => (
            <a
              key={l.href}
              href={l.href}
              className="rounded-full px-3.5 py-1.5 text-[13px] font-medium text-muted-foreground transition-colors hover:bg-white/[0.05] hover:text-foreground"
            >
              {l.label}
            </a>
          ))}
        </div>
        <a
          href="#onchain"
          className="flex items-center gap-2 rounded-full border border-veil-emerald/30 bg-veil-emerald/10 px-3 py-1.5 text-[12px] font-semibold text-veil-emerald"
        >
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-veil-emerald opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-veil-emerald" />
          </span>
          Live · testnet
        </a>
      </nav>
    </motion.header>
  );
}
