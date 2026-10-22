// Offline test for the contract-error humanizer: a raw soroban HostError string
// carrying `Error(Contract, #NNNN)` must map to a friendly message for known
// codes, and pass through unknown / non-contract errors; and
// ChainClient.confidentialBalance must read only AccountNotRegistered (3501) as
// "not registered". Runs with no infra.

import { humanizeContractError, parseContractErrorCode, CONTRACT_ERRORS } from "../src/chain/errors.ts";

let pass = 0,
  fail = 0;
function check(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.error(`  ✗ ${name}${detail ? `\n      ${detail}` : ""}`);
  }
}

// The exact shape the RPC/SDK surfaces for a frozen account on deposit.
const FROZEN_RAW =
  'simulate deposit failed: HostError: Error(Contract, #3601) Event log (newest first): 0: [Diagnostic Event] ...';

check("parses code from a real HostError string", parseContractErrorCode(FROZEN_RAW) === 3601);
check(
  "frozen (3601) → friendly message",
  humanizeContractError(FROZEN_RAW) === CONTRACT_ERRORS[3601],
  humanizeContractError(FROZEN_RAW),
);
check("3601 message mentions frozen", /frozen/i.test(CONTRACT_ERRORS[3601]));
check("not-registered (3501) maps", humanizeContractError("Error(Contract, #3501)") === CONTRACT_ERRORS[3501]);
check(
  "policy denial (3602) maps",
  humanizeContractError("HostError: Error(Contract, #3602)") === CONTRACT_ERRORS[3602],
);
// v0.8.0 additions: clawback preconditions, the verifier/auditor registries,
// and the crypto point decoder all surface through the same humanizer.
for (const code of [1403, 2010, 2203, 3303, 3403, 3604, 3605, 3606]) {
  check(`${code} maps`, humanizeContractError(`Error(Contract, #${code})`) === CONTRACT_ERRORS[code]);
}
check("3604 message mentions frozen", /frozen/i.test(CONTRACT_ERRORS[3604]));
check(
  "unknown contract code → generic contract message",
  humanizeContractError("Error(Contract, #9999)") === "The contract rejected the operation (error #9999).",
);
check("non-contract error → null (passes through)", humanizeContractError("Freighter not detected") === null);
check("no code present → null", parseContractErrorCode("some random text") === null);

// confidential_balance: only AccountNotRegistered (3501) means "not
// registered"; any other failure must propagate, never read as an empty account.
{
  const { ChainClient, SimulationFailedError } = await import("../src/chain/client.ts");
  const clientThrowing = (err) => {
    const c = new ChainClient({
      rpcUrl: "http://127.0.0.1:1",
      networkPassphrase: "Test SDF Network ; September 2015",
      contracts: { token: "CCREDIB3DG3IBVUKBL7QMEK4MTPSTODR7MQ34QY4SQ5LZ5L4WFWNVNXG", verifier: "", auditor: "" },
    });
    c.simulateAt = async () => { throw err; };
    return c;
  };
  const { Keypair } = await import("@stellar/stellar-sdk");
  const ACCOUNT = Keypair.random().publicKey();
  const notRegistered = new SimulationFailedError(
    "confidential_balance",
    "HostError: Error(Contract, #3501)\n\nEvent log (newest first):\n" +
      "   0: [Diagnostic Event] topics:[error, Error(Contract, #3501)]",
    777,
  );
  check(
    "simulation error keeps the humanizable message",
    notRegistered.message.startsWith("simulate confidential_balance failed: HostError: Error(Contract, #3501)") &&
      parseContractErrorCode(notRegistered.message) === 3501,
  );
  check(
    "confidentialBalance: AccountNotRegistered (3501) → null",
    (await clientThrowing(notRegistered).confidentialBalance(ACCOUNT)) === null,
  );
  const at = await clientThrowing(notRegistered).confidentialBalanceAt(ACCOUNT);
  check("confidentialBalanceAt: not registered carries the read's ledger", at.account === null && at.latestLedger === 777);
  check("isRegistered: AccountNotRegistered (3501) → false", (await clientThrowing(notRegistered).isRegistered(ACCOUNT)) === false);
  for (const [label, err] of [
    ["transport failure", new Error("connect ECONNREFUSED 127.0.0.1:1")],
    ["storage error (archived entry)", new SimulationFailedError("confidential_balance", "HostError: Error(Storage, MissingValue)", 777)],
    ["another contract error", new SimulationFailedError("confidential_balance", "HostError: Error(Contract, #3601)", 777)],
  ]) {
    const got = await clientThrowing(err).confidentialBalance(ACCOUNT).catch((e) => e);
    check(`confidentialBalance: ${label} propagates`, got === err, String(got));
    const reg = await clientThrowing(err).isRegistered(ACCOUNT).catch((e) => e);
    check(`isRegistered: ${label} propagates`, reg === err, String(reg));
  }
}

console.log(`\ncontract-errors: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
