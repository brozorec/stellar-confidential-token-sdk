// Browser-safe barrel: only the prover (bb.js, isomorphic). The Node-only
// circuit loader lives in ./artifacts.js (node:fs) and is imported directly by
// CLI scripts / tests; the browser imports circuit JSON through its bundler.
export * from "./prover.js";
