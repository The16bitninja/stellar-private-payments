/** Ambient animated background: drifting aurora blobs + a masked grid. */
export function Aurora() {
  return (
    <div className="pointer-events-none fixed inset-0 -z-10 overflow-hidden">
      <div className="absolute inset-0 grid-bg opacity-70" />
      <div
        className="absolute -left-[10%] -top-[15%] h-[55vh] w-[55vh] rounded-full animate-aurora blur-[90px]"
        style={{ background: "radial-gradient(circle, #8b5cf6 0%, transparent 65%)" }}
      />
      <div
        className="absolute right-[-10%] top-[4%] h-[50vh] w-[50vh] rounded-full animate-aurora blur-[100px]"
        style={{
          background: "radial-gradient(circle, #22d3ee 0%, transparent 65%)",
          animationDelay: "-5s",
        }}
      />
      <div
        className="absolute bottom-[-20%] left-[28%] h-[60vh] w-[60vh] rounded-full animate-aurora blur-[110px]"
        style={{
          background: "radial-gradient(circle, #6366f1 0%, transparent 65%)",
          animationDelay: "-10s",
        }}
      />
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-background/40 to-background" />
    </div>
  );
}
