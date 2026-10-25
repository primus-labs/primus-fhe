# primus_glwe benchmarks

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> [Primus FHE](../../../README.md) is experimental; its APIs and numerical contracts are unstable and may change incompatibly at any time.

## Workloads

| Target | Timed work |
| --- | --- |
| [encryption](encryption.rs) | Secret/public encryption and secret decryption, including coefficient NTT paths; GLev/GGSW generation and batches of 8 constant GGSWs |
| [primitives](primitives.rs) | Trace/reverse trace, projection, partial/full expansion, trace packing and direct Fourier automorphism |
| [key_conversion](key_conversion.rs) | Independent-key LWE packing and coefficient GLev to transformed GGSW scheme switching |

Key/table setup and buffer allocation stay outside timing. Encryption includes sampling, encoding and required transforms. Parameters and fixed seeds are in each file; these workloads do not establish matched security across backends.

Ordinary and reverse trace have different output scales. Projection and partial expansion use the same zero-tail message and report output-message throughput. Trace packing uses the flattened GLWE secret and spaced slots; independent-key packing uses consecutive slots. Compare these endpoints according to the desired operation.

## Run

```sh
cargo bench -p primus_glwe --bench encryption --features ntt,rustfft
cargo bench -p primus_glwe --bench primitives --features ntt,rustfft,tfhe-fft
cargo bench -p primus_glwe --bench key_conversion --features ntt,rustfft
```

Append `-- '<regex>'` to select cases, or `-- --test` to run a smoke check without timing samples. These feature lists include each target's required FFT engines. Validation commands are in the workspace [testing guide](../../../guides/development/testing.md).
