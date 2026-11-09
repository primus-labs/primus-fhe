#!/usr/bin/env python3
"""Offline *bare-LWE reference* screening; this is not an RLWE/KDM security proof.

Run with Sage's Python and an explicitly supplied lattice-estimator checkout.
Input is a JSON array of public domains: label, n, data_q, key_p, secret/error
distributions, samples and target_bits. Distribution objects are either
{"kind":"cbd","eta":21}, {"kind":"uniform_ternary"}, or
{"kind":"uniform_binary"}. Unsupported distributions are rejected rather than
substituted by a Gaussian with the same variance. Computation-only BFV P must
not be included as key_p. No Rust constructor imports these results as a proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estimator", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.resolve() == args.input.resolve():
        raise ValueError("input and output must be different files")
    # Failed reruns must not leave an earlier complete report looking current.
    args.output.write_text('{"complete": false, "results": []}\n', encoding="utf-8")
    estimator = args.estimator.resolve()
    # The explicit source path takes precedence over any installed estimator.
    sys.path.insert(0, str(estimator))
    from estimator import LWE, ND, RC
    from sage.all import ZZ, log, oo
    from sage.version import version as sage_version

    def distribution(spec: dict):
        if spec == {"kind": "uniform_ternary"}:
            return ND.Uniform(-1, 1)
        if spec == {"kind": "uniform_binary"}:
            return ND.Uniform(0, 1)
        if set(spec) == {"kind", "eta"} and spec["kind"] == "cbd":
            eta = spec["eta"]
            if type(eta) is int and 1 <= eta <= 32:
                return ND.CenteredBinomial(eta)
        raise ValueError(f"unsupported exact distribution: {spec!r}")

    def git(*command: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(estimator), *command], text=True,
        ).strip()

    source_hash = hashlib.sha256()
    for path in sorted((estimator / "estimator").rglob("*.py")):
        source_hash.update(str(path.relative_to(estimator)).encode() + b"\0")
        source_hash.update(path.read_bytes())
    provenance = {
        "estimator_commit": git("rev-parse", "HEAD"),
        "estimator_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
        "estimator_python_sha256": source_hash.hexdigest(),
        "sage": sage_version,
        "adapter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "input_sha256": hashlib.sha256(args.input.read_bytes()).hexdigest(),
        "attacks": ["primal_usvp", "primal_bdd", "dual_hybrid"],
        "models": ["ADPS16", "MATZOV"],
        "primal_shape_model": "gsa",
        "sample_assumption": "explicit independent bare-LWE proxy; not a count of independent RLWE ring rows",
        "scope": "finite bare-LWE cost reference only; not RLWE, related-key or joint security",
    }
    rows = json.loads(args.input.read_text(encoding="utf-8"))
    if not isinstance(rows, list) or not rows:
        raise ValueError("input must be a nonempty array")
    results = []
    for row in rows:
        n = row["n"]
        samples = row["samples"]
        target = row["target_bits"]
        if any(type(x) is not int or x <= 0 for x in (n, samples, target)):
            raise ValueError("n, samples and target_bits must be positive integers")
        if n & (n - 1):
            raise ValueError("ordinary ring N must be a power of two")
        raw_primes = row["data_q"] + row["key_p"]
        if any(type(q) is not int or q < 2 for q in raw_primes):
            raise ValueError("domain primes must be exact positive JSON integers")
        primes = [ZZ(q) for q in raw_primes]
        if not row["data_q"] or len(set(primes)) != len(primes):
            raise ValueError("Q/optional key P must be nonempty and jointly distinct")
        if any(not q.is_prime() or (q - 1) % (2 * n) for q in primes):
            raise ValueError("each domain modulus must be a prime congruent to 1 modulo 2N")
        q = ZZ(1)
        for prime in primes:
            q *= prime
        params = LWE.Parameters(
            n=n, q=q, Xs=distribution(row["secret"]),
            Xe=distribution(row["error"]), m=samples, tag=row["label"],
        )
        costs = []
        for model_name in provenance["models"]:
            model = getattr(RC, model_name)
            attacks = (
                ("primal_usvp", LWE.primal_usvp),
                ("primal_bdd", LWE.primal_bdd),
                ("dual_hybrid", LWE.dual_hybrid),
            )
            for attack_name, attack in attacks:
                shape = {"red_shape_model": "gsa"} if attack_name.startswith("primal_") else {}
                cost = attack(params, red_cost_model=model, **shape)
                rop = cost["rop"]
                # A missing/failed attack raises; infinity is a non-applicable
                # model result, never a replacement for an execution failure.
                bits = None if rop == oo else float(log(rop, 2))
                costs.append({"model": model_name, "attack": attack_name, "bits": bits})
                print(row["label"], model_name, attack_name, bits, flush=True)
        finite = [cost["bits"] for cost in costs if cost["bits"] is not None]
        if not finite:
            raise ValueError("no finite attack cost; reference target remains unevaluated")
        minimum = min(finite)
        results.append({
            **row, "exposed_modulus": str(q), "exposed_bits": int(q.nbits()),
            "costs": costs, "minimum_reference_bits": minimum,
            "meets_reference_target": minimum >= target,
        })
        args.output.write_text(
            json.dumps({
                "provenance": provenance, "complete": len(results) == len(rows),
                "input_domains": len(rows), "results": results,
            }, indent=2) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
