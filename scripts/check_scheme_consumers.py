#!/usr/bin/env python3
"""Run the basic BFV/BGV examples with radix and native Hybrid keys as isolated normal-dependency consumers.

No workspace development dependencies or feature selections are inherited. Use
--output-dir outside this repository to retain source, manifests, lockfiles,
command output and normal dependency trees. Build artifacts remain reusable in
target/scheme-consumers; this script needs only Python's standard library.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = re.compile(r'\b(?:criterion|dashu-int)(?: v[0-9]| feature ")')


def dependency(name: str, batching: bool = False) -> str:
    path = json.dumps(str(ROOT / "crates" / name))
    features = ', features = ["batching"]' if batching else ""
    return f"{name} = {{ path = {path}, default-features = false{features} }}"


def run(command: list[str], directory: Path, log: str, env: dict[str, str]) -> str:
    result = subprocess.run(
        command, cwd=directory, env=env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    output = "$ " + " ".join(command) + "\n" + result.stdout
    (directory / log).write_text(output, encoding="utf-8")
    if result.returncode:
        raise RuntimeError(f"{directory.name}: command failed ({result.returncode})\n{output}")
    return result.stdout


def check_consumers(output_dir: Path) -> None:
    output_dir = output_dir.resolve()
    if output_dir == ROOT or ROOT in output_dir.parents:
        raise ValueError("--output-dir must be outside the FHE repository")
    output_dir.mkdir(parents=True, exist_ok=True)
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    rand = workspace["workspace"]["dependencies"]["rand"]
    rand_version = rand if isinstance(rand, str) else rand["version"]
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(ROOT / "target" / "scheme-consumers")
    for scheme in ("bfv", "bgv"):
        for example in ("coefficients", "slots"):
            name = f"{scheme}_{example}"
            directory = output_dir / name
            (directory / "src").mkdir(parents=True, exist_ok=True)
            batching = example == "slots"
            dependencies = [dependency(f"primus_{scheme}", batching)]
            dependencies.extend(dependency(crate) for crate in (
                "primus_decompose", "primus_glwe_rns", "primus_modulus",
                "primus_shape",
            ))
            if batching:
                dependencies.append(dependency("primus_poly"))
            dependencies.append(f"rand = {json.dumps(rand_version)}")
            manifest = (
                f'[package]\nname = "primus_scheme_consumer_{name}"\n'
                'version = "0.0.0"\nedition = "2024"\n\n'
                '[workspace]\nresolver = "3"\n\n[dependencies]\n'
                + "\n".join(dependencies) + "\n"
            )
            (directory / "Cargo.toml").write_text(manifest, encoding="utf-8")
            shutil.copyfile(
                ROOT / "crates" / f"primus_{scheme}" / "examples" / f"{example}.rs",
                directory / "src" / "main.rs",
            )
            # Each package owns an independent lock and feature resolution. The
            # tree uses the same target and dependency kinds as `cargo run`.
            run(["cargo", "generate-lockfile", "--offline"], directory, "lock.log", env)
            metadata = json.loads(run(
                ["cargo", "metadata", "--offline", "--locked", "--no-deps", "--format-version=1"],
                directory, "metadata.log", env,
            ))
            if Path(metadata["workspace_root"]).resolve() != directory:
                raise RuntimeError(f"{name}: consumer inherited a different Cargo workspace")
            if any(dep["kind"] is not None for dep in metadata["packages"][0]["dependencies"]):
                raise RuntimeError(f"{name}: consumer has non-normal dependencies")
            tree = run(
                ["cargo", "tree", "--offline", "--locked", "-e", "normal,features"],
                directory, "tree.log", env,
            )
            if FORBIDDEN.search(tree):
                raise RuntimeError(f"{name}: test/benchmark dependency leaked into normal tree")
            if not batching and 'feature "batching"' in tree:
                raise RuntimeError(f"{name}: coefficient consumer unexpectedly enabled batching")
            if batching and 'primus_encoding feature "batching"' not in tree:
                raise RuntimeError(f"{name}: scheme batching did not enable the shared encoder")
            run(["cargo", "run", "--offline", "--locked"], directory, "run.log", env)
            run(["cargo", "run", "--offline", "--locked", "--", "--hybrid"], directory, "run-hybrid.log", env)
            print(f"{name}: radix and Hybrid normal requests passed; no criterion/dashu-int", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, help="retain evidence outside this repository")
    args = parser.parse_args()
    if args.output_dir is not None:
        check_consumers(args.output_dir)
    else:
        with tempfile.TemporaryDirectory(prefix="primus-scheme-consumers-") as temporary:
            check_consumers(Path(temporary))


if __name__ == "__main__":
    main()
