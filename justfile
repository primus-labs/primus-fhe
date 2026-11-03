set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]
export RUSTDOCFLAGS := "-D warnings"

default: fmt-check (lint "*" "ntt,fourier,rustfft,tfhe-fft") (test "*" "ntt,fourier,rustfft,tfhe-fft")

# CI selects stable; local commands use the active toolchain.
ci: default test-doc schemes
  cargo check -p primus_data --lib --no-default-features
  cargo check -p primus_fft -p primus_lwe -p primus_tfhe_glwe -p primus_tfhe_ntru --lib --no-default-features
  cargo check -p 'primus_tfhe*_ntt' -p primus_glwe_rns --lib --no-default-features
  cargo check -p 'primus_tfhe*_fourier' --lib --no-default-features --features rustfft
  cargo check -p primus_encoding --lib --no-default-features
  cargo check -p primus_encoding --lib --no-default-features --features batching
  cargo check -p primus_bgv --lib --no-default-features
  cargo check -p primus_modulus --all-targets --features derive
  cargo nextest run -p primus_modulus --lib --tests --features derive -E 'binary(derives)'
  cargo check -p primus_distr --lib --features high_precision

# Separate toolchain/job. Build strict rustdoc only once, with all features.
ci-nightly: simd
  cargo +nightly test --workspace --doc --all-features
  cargo +nightly doc --workspace --no-deps --document-private-items --all-features
  cargo +nightly check -p primus_modulus -p primus_encoding -p primus_tfhe_glwe -p primus_tfhe_ntru --lib --no-default-features --features simd

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
tfhe: (lint "primus_tfhe*" "ntt,fourier,rustfft,tfhe-fft") (test "primus_tfhe*" "ntt,fourier,rustfft,tfhe-fft")

tfhe-simd: (simd "primus_tfhe*")

# BFV/BGV optional batching, independent from the default coefficient workflow.
schemes:
  cargo clippy -p primus_encoding -p primus_bfv -p primus_bgv --all-targets --features rns,batching -- -D warnings
  cargo nextest run -p primus_encoding -p primus_bfv -p primus_bgv --lib --tests --features rns,batching
  cargo run -p primus_bgv --example coefficients
  cargo run -p primus_bgv --example slots --features batching
  cargo run -p primus_bgv --example leveled_coefficients
  cargo run -p primus_bgv --example leveled_slots --features batching
  cargo run -p primus_bfv --example slots --features batching

# Explicit crate-local workload.
bench package target *cargo-args:
  cargo bench -p '{{package}}' --bench '{{target}}' {{cargo-args}}

# Explicit target, one Criterion process, no statistical sampling.
bench-smoke package target *cargo-args:
  cargo bench -p '{{package}}' --bench '{{target}}' {{cargo-args}} -- --test

new-lib name:
  cargo new crates/{{name}} --lib
