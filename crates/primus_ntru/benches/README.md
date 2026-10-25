# primus_ntru benchmarks

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> [Primus FHE](../../../README.md) is experimental; its APIs and numerical contracts are unstable and may change incompatibly at any time.

## Workloads

| Target | Timed work |
| --- | --- |
| [encryption](encryption.rs) | Ordinary message encryption and undecoded phase extraction |
| [primitives](primitives.rs) | Key switching, coefficient/transformed automorphism, trace/reverse trace, projection, partial expansion and scheme switching |
| [constant_gadget](constant_gadget.rs) | Constant NLev generation and batches of 8 signed NGSW controls |
| [lwe_return](lwe_return.rs) | Q→q conversion, extraction and LWE key switching; individual returns versus shared-input batch returns |
| [ternary_cmux](ternary_cmux.rs) | One fused ternary rotation versus two binary CMUXes, using encrypted controls |

Key/table setup and buffer allocation stay outside timing. Encryption includes sampling, encoding and required transforms. Parameters and fixed seeds are in each file; these workloads do not establish matched security across backends.

Phase extraction does not include decoding. Trace and reverse trace have different output scales. `lwe_return` excludes blind rotation; its inputs are canonical coefficient polynomials. `ternary_cmux` compares the complete rotation in each path; Fourier results can have different rounding errors.

## Run

```sh
cargo bench -p primus_ntru --bench encryption --features ntt,rustfft,tfhe-fft
cargo bench -p primus_ntru --bench primitives --features ntt,rustfft,tfhe-fft
cargo bench -p primus_ntru --bench constant_gadget --features ntt,rustfft
cargo bench -p primus_ntru --bench lwe_return
cargo bench -p primus_ntru --bench ternary_cmux --features ntt,rustfft,tfhe-fft
```

Append `-- '<regex>'` to select cases, or `-- --test` to run a smoke check without timing samples. These feature lists include each target's required FFT engines. Validation commands are in the workspace [testing guide](../../../guides/development/testing.md).
