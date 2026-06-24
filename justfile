set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

simd-packages := "-p primus_integer -p primus_modulus -p primus_barrett_derive -p primus_factor"
simd-features := "primus_integer/simd,primus_modulus/simd,primus_barrett_derive/simd,primus_factor/simd"

default: fmt check lint test

ci: fmt-check check lint test simd

simd: check-simd lint-simd test-simd

new-lib name:
  cargo new crates/{{name}} --lib

fmt:
  cargo fmt --all

fmt-check:
  cargo fmt --all -- --check

check:
  cargo check --workspace --all-targets

check-simd:
  cargo +nightly check {{simd-packages}} --all-targets --features {{simd-features}}

lint:
  cargo clippy --workspace --all-targets -- -D warnings

lint-simd:
  cargo +nightly clippy {{simd-packages}} --all-targets --features {{simd-features}} -- -D warnings

test:
  cargo nextest run --workspace --all-targets

test-simd:
  cargo +nightly nextest run {{simd-packages}} --all-targets --features {{simd-features}}
