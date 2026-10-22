#!/usr/bin/env bash
# Fails if any given compiled circuit could feed witness data into
# Barretenberg's plookup argument.
#
#   scripts/check-witness-lookups.sh [artifact.json ...]
#
# Defaults to every circuit artifact this package ships. Port of upstream's
# packages/confidential/circuits/scripts/check_witness_lookups.sh (v0.8.0),
# taking artifact paths instead of compiling a workspace.
#
# Proofs are generated without ZK, so `lookup_read_counts` and
# `lookup_read_tags` are committed in the clear and every lookup whose table
# row depends on a witness exposes that row. bb lowers MULTI_SCALAR_MUL to its
# fixed-base lookup tables whenever a base point is an ACIR constant equal to
# one of its precomputed generators, which `G` and `H` are; `commit` and
# `scalar_mul` in the circuit library pass them as witnesses to prevent that.
# This script inspects the compiled ACIR for the two ways that can regress: a
# blackbox outside the plookup-free set below, or a MULTI_SCALAR_MUL base
# point with a constant coordinate.
#
# Requires `noir-inspector`, which ships with nargo 1.0.0-beta.11.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$#" -eq 0 ]; then
    set -- circuits/*.json circuits/disclosure/*.json
fi

# Blackboxes that bb 0.87.0 lowers without plookup: POSEIDON2_PERMUTATION to
# Poseidon2 gates, RANGE to delta-range gates, MULTI_SCALAR_MUL with witness
# bases to ROM-based Straus tables.
ALLOWED="MULTI_SCALAR_MUL POSEIDON2_PERMUTATION RANGE"

status=0
for artifact in "$@"; do
    case "$(basename "$artifact")" in manifest.json | *.vk.json) continue ;; esac
    if ! noir-inspector print-acir "$artifact" | awk -v file="$artifact" -v allowed="$ALLOWED" '
        BEGIN { n = split(allowed, a, " "); for (i = 1; i <= n; i++) ok[a[i]] = 1 }
        match($0, /BLACKBOX::[A-Z0-9_]+/) {
            name = substr($0, RSTART + 10, RLENGTH - 10)
            if (!(name in ok)) {
                printf "%s: BLACKBOX::%s is not in the plookup-free set\n", file, name
                bad = 1
                next
            }
            if (name != "MULTI_SCALAR_MUL") next
            # Operands are 3 per point (x, y, is_infinite), then 2 per scalar.
            ops = $0
            sub(/^[^[]*\[/, "", ops)
            sub(/\].*$/, "", ops)
            k = 0
            while (match(ops, /\([^)]*\)/)) {
                op = substr(ops, RSTART + 1, RLENGTH - 2)
                sub(/,.*/, "", op)
                vals[k++] = op
                ops = substr(ops, RSTART + RLENGTH)
            }
            if (k == 0 || k % 5 != 0) {
                printf "%s: cannot parse MULTI_SCALAR_MUL operands: %s\n", file, $0
                bad = 1
                next
            }
            for (p = 0; p < k / 5; p++) {
                if (vals[3 * p] !~ /^_/ || vals[3 * p + 1] !~ /^_/) {
                    printf "%s: MULTI_SCALAR_MUL takes a constant base point\n", file
                    bad = 1
                    break
                }
            }
        }
        END { exit bad }
    '; then
        status=1
    else
        echo "ok  $artifact"
    fi
done

if [ "$status" -ne 0 ]; then
    echo "Witness data can reach a lookup table; see the header of $0." >&2
fi
exit "$status"
