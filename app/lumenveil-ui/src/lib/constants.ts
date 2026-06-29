// Real Lumenveil testnet deployment (Day-5 capstone).
export const CHAIN = {
  network: "testnet",
  pool: "CBX7YVYTTTOAMAP4BD727SFNVES2Y6UBKMQC243SKTAOJT5LE7ED52V4",
  registry: "CBJT4I7KB4WHIPHFHYFUBZSQNBUY4GYD5TXJNUANAK5WI73BGACGAIEC",
  verifier: "CB2OYSTWNSQWF62LLJKIGPO6VXMETGEPUX747IXBCL6H7RJRHL3QCFPT",
  deployer: "GBLK2CTOGPTSHKHLKGCH3IFFMFLC3QDGGWFU7O6O65L3OMV5LLJ34AJG",
  // The auditor's demo Baby JubJub secret (so the loop is runnable end-to-end).
  demoSecret: "1234567890123456789",
  rpcUrl: "https://soroban-testnet.stellar.org",
  startLedger: 3315719,
  txs: {
    deploy: "c971654efa19d22acd098a649d56c1809743e4a1b44ffe366cf2c608280fe9b4",
    pin: "d3593fe369f52158f2664749c31edcdb26598f8cc19ca7743a5c8c3d7918b3e0",
    disclose: "ce9e074e470768d0a3b6daaa295c72b69afc4c4b5ac9ac43e07f9dc9e63ac6cc",
  },
} as const;

export const expertTx = (h: string) =>
  `https://stellar.expert/explorer/testnet/tx/${h}`;
export const expertContract = (c: string) =>
  `https://stellar.expert/explorer/testnet/contract/${c}`;
