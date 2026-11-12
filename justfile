set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]
export RUSTDOCFLAGS := "-D warnings"

stable_ci_features := "ntt,fourier,rustfft,tfhe-fft,rns,batching,derive,high_precision"
parallel_packages := "-p primus_ntt -p primus_lattice -p primus_bfv -p primus_bgv"
parallel_features := "rns,batching,parallel"
ci_parallel_tests := "--test dcrt_prefix --test leveled_parameters"

default: fmt-check (lint "*" "ntt,fourier,rustfft,tfhe-fft") (test "*" "ntt,fourier,rustfft,tfhe-fft")

# CI selects stable; local commands use the active toolchain.
ci: fmt-check ci-stable-check ci-stable-lint ci-stable-test

ci-stable-check:
  # The isolated consumers resolve their own lockfiles offline.
  cargo fetch --target host-tuple
  cargo check -p primus_data -p primus_encoding --lib --no-default-features
  cargo check -p primus_fft -p primus_lwe -p primus_tfhe_glwe -p primus_tfhe_ntru --lib --no-default-features
  cargo check -p 'primus_tfhe*_ntt' --lib --no-default-features
  cargo check -p 'primus_tfhe*_fourier' --lib --no-default-features --features rustfft
  cargo check -p primus_encoding --lib --no-default-features --features batching
  python3 scripts/check_scheme_consumers.py --check-only

ci-stable-lint: (lint "*" stable_ci_features) (parallel-lint ("--lib " + ci_parallel_tests))

ci-stable-test: (test "*" stable_ci_features) (parallel-test ci_parallel_tests)
  cargo nextest run -p primus_bfv -p primus_bgv --test allocation --no-default-features
  cargo nextest run -p primus_ntru --test lwe_key_switch --no-default-features
  cargo test --workspace --doc --features '{{stable_ci_features}}'

ci-nightly: ci-nightly-check simd ci-nightly-doc

ci-nightly-check:
  cargo +nightly check -p primus_modulus -p primus_encoding -p primus_tfhe_glwe -p primus_tfhe_ntru --lib --no-default-features --features simd

ci-nightly-doc:
  cargo +nightly doc --workspace --no-deps --document-private-items --all-features

fmt:
  cargo fmt --all

fmt-check:
  cargo fmt --all -- --check

check package="*" features="":
  cargo check -p '{{package}}' --features '{{features}}' --all-targets

lint package="*" features="":
  cargo clippy -p '{{package}}' --features '{{features}}' --all-targets -- -D warnings

# All-targets is for compilation; keep Criterion out of nextest.
test package="*" features="":
  cargo nextest run -p '{{package}}' --features '{{features}}' --lib --tests

# Nextest does not execute doctests.
test-doc package="*":
  cargo test -p '{{package}}' --doc

simd package="*":
  cargo +nightly clippy -p '{{package}}' --all-targets --all-features -- -D warnings
  cargo +nightly nextest run -p '{{package}}' --lib --tests --all-features

# TFHE examples, libraries and small numerical regressions, including both FFT engines.
tfhe: (lint "primus_tfhe*" "rustfft,tfhe-fft") (test "primus_tfhe*" "rustfft,tfhe-fft")

tfhe-simd: (simd "primus_tfhe*")

# BFV/BGV ordinary requests, advanced batching, and normal external consumers.
schemes: && scheme-smoke
  cargo clippy -p primus_encoding -p primus_bfv -p primus_bgv --all-targets --features rns,batching -- -D warnings
  cargo nextest run -p primus_encoding -p primus_bfv -p primus_bgv --lib --tests --features rns,batching

# The standalone consumers also run the ordinary examples and both key backends.
[private]
scheme-smoke:
  cargo run -p primus_bgv --example leveled_slots --features batching
  cargo run -p primus_bfv --example explicit_coefficients
  cargo run -p primus_bfv --example subring_slots --features batching
  cargo run -p primus_bfv --example leveled_coefficients
  cargo run -p primus_bfv --example leveled_slots --features batching
  cargo run -p primus_glwe_rns --example raw_encryption
  cargo run -p primus_glwe_rns --example public_encryption
  cargo run -p primus_glwe_rns --example gadget_encryption
  python3 scripts/check_scheme_consumers.py

# Run the full Stable parallel matrix manually.
parallel targets="--lib --tests": parallel-lint (parallel-test targets)

[private]
parallel-lint targets="--all-targets":
  cargo clippy {{parallel_packages}} {{targets}} --features '{{parallel_features}}' -- -D warnings

[private]
parallel-test targets:
  env RAYON_NUM_THREADS=4 cargo nextest run {{parallel_packages}} {{targets}} --features '{{parallel_features}}'

# Explicit crate-local workload.
bench package target *cargo-args:
  cargo bench -p '{{package}}' --bench '{{target}}' {{cargo-args}}

# Explicit target, one Criterion process, no statistical sampling.
bench-smoke package target *cargo-args:
  cargo bench -p '{{package}}' --bench '{{target}}' {{cargo-args}} -- --test

new-lib name:
  cargo new crates/{{name}} --lib
