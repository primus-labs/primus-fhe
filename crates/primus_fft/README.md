# primus_fft

English | [简体中文](README.zh_CN.md)

`primus_fft` provides negacyclic Fourier transforms for polynomials in `Z[X] / (X^N + 1)`. It exposes a common table-and-workspace API over RustFFT and `tfhe-fft`, together with the torus conversions used by the Fourier FHE paths in [Primus FHE](../../README.md).

> [!WARNING]
> This crate is part of the experimental Primus FHE workspace. Its API, Fourier representation, and numerical contracts are unstable and may change incompatibly at any time.

## Core types

| Type | Role |
| --- | --- |
| `FftTable` | Backend-independent negacyclic transform contract for one polynomial length |
| `RustFftTable` | `FftTable` implementation backed by RustFFT |
| `TfheFftTable` | `FftTable` implementation backed by the unordered `tfhe-fft` plan |
| `FftEngine<'a, Table>` | A reference to one immutable table plus one reusable mutable workspace |
| `TorusFftValue` | Conversion between unsigned `u16`, `u32`, or `u64` torus bit patterns and `f64` |

For `N = 2^log_n`, a transform maps `N` coefficients to `N / 2` complex values. Construct a table once and reuse an engine for repeated transforms.

## Features

No FFT engine is enabled by default. `FftTable`, `FftEngine`, `Complex64`, and `TorusFftValue` are always available.

- `rustfft` exports `RustFftTable` / `RustFftWorkspace`.
- `tfhe-fft` exports `TfheFftTable` / `TfheFftWorkspace`.

Both may be enabled together. Custom `FftTable` implementations can use the common API with the default features.

## Example

Add `primus_fft` with the `rustfft` feature and `primus_shape` as direct dependencies.

```rust
use primus_fft::{Complex64, FftEngine, FftTable, RustFftTable};
use primus_shape::PolyLength;

let table = RustFftTable::new(PolyLength::new(32)); // N = 32
let mut fft = FftEngine::new(&table);
let input: Vec<u32> = (0..fft.poly_length().get()).map(|value| value as u32).collect();
let mut fourier = vec![Complex64::default(); fft.fourier_length()];
let mut output = vec![0u32; fft.poly_length().get()];

fft.forward_as_torus(&input, &mut fourier);
fft.backward_as_torus(&fourier, &mut output);

assert_eq!(output, input);
```

## Transform variants

- `forward_as_torus` reinterprets each unsigned word as its signed bit pattern, then scales it by `2^-BITS`. For example, `u32::MAX` represents `-1 / 2^32`.
- `forward_as_integer` performs the same signed-bit-pattern interpretation without torus scaling. It is intended for small integer polynomials such as secret keys and decomposition digits.
- `backward_as_torus` applies the inverse transform, torus scaling, rounding, and wrapping conversion back to the selected unsigned word type.

A negacyclic convolution uses `forward_as_torus` for a torus polynomial, `forward_as_integer` for an integer polynomial, point-wise complex multiplication, and then `backward_as_torus`.

## Table and workspace contract

Fourier values and workspace must come from the **same table instance**. Independently constructed tables are not interchangeable, even with the same backend and length. Length or capacity checks do not validate this identity; callers must preserve it.

Tables are immutable and implement `Send + Sync`. Share the table across threads, with a separate `FftEngine` or `new_workspace()` result for each concurrent worker. Inputs and outputs accept ordinary slices, including subslices, without extra alignment requirements.

Input and output lengths must match exactly; otherwise transforms panic:

- coefficient slices contain `poly_length().get()` values;
- Fourier slices contain `fourier_length() == poly_length().fourier_poly_len()` values.

See the [table and engine API](src/table.rs) for complete method contracts.

Built-in workspaces erase their buffers on drop; `fft.zeroize_workspace()` erases them without releasing the allocation. Transforms do not erase scratch after each call. Caller-owned inputs/outputs, registers and stack copies are outside this buffer guarantee; custom backends define their own erasure behavior.

`FftTable::automorphism_map(degree)` allocates a reusable `X -> X^degree` map for odd `degree` in `[1, 2N)`. Entry `j` gives `(source, conjugate)` for output `j`. Keep the map bound to its originating table's Fourier order; applying it alone does not perform cryptographic key switching.

## Length and precision

`FftTable::new` takes [`primus_shape::PolyLength`](../primus_shape/README.md#polynomial-length). Build the table outside repeated transform paths to reuse its plan and allocations.

Transforms use `f64` and are approximate; a word-wide torus input is not guaranteed to round-trip bit-for-bit. Correct rounding depends on accumulated floating-point error and integer operand magnitudes, so the surrounding algorithm must maintain a suitable precision budget. Conversion and rounding rules are in the [torus API](src/torus.rs).

## Testing and benchmarks

See the workspace [testing guide](../../guides/development/testing.md) and the
[`fft` benchmark](benches/fft.rs) for commands, engine features and workloads.

## License

Licensed under either the [Apache License, Version 2.0](../../LICENSE-APACHE-2.0) or the [MIT License](../../LICENSE-MIT), at your option.
