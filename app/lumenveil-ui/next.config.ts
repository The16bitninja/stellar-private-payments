import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Keep the Stellar SDK out of the server bundle (it's a large dep used only at
  // request time inside the route handlers).
  serverExternalPackages: ["@stellar/stellar-sdk"],
  // Pin the workspace root (the repo has several lockfiles).
  turbopack: { root: import.meta.dirname },
};

export default nextConfig;
