# primus_tfhe

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Shared LWE clients, LUT compilers and PBS interfaces for GLWE and NTRU. Start with a concrete backend for complete examples.

## Choosing an operation

Let `t` be the input message modulus, `N` the ring length and `k` the output count. Ordinary PBS uses unsigned Rounded input.

| Task | Input domain | Program and output |
| --- | --- | --- |
| Unary function | Front half `0..ceil(t/2)` | `compile_fn` or `compile_slice`, one Rounded LWE |
| Odd full domain | `0..t`, odd `3 ≤ t ≤ N` | `compile_odd_full_domain_fn` or `compile_odd_full_domain_slice`, one Rounded LWE |
| ManyLUT | One front-half input, `ceil(t/2) ≤ N/next_power_of_two(k)` | `compile_interleaved_fn` or `compile_interleaved_slice`, k Rounded LWEs |
| Factorized MVB | One nonempty front-half prefix | `compile_mvb_fn`, k Scaled LWEs |
| Bounded two-input function | `x<B`, `y<R`, `B*R≤ceil(t/2)` | `BivariateLookupTable`, one Rounded LWE |
| Boolean gates | Rounded 0/1 at t=4 | `BooleanEvaluator`, Boolean LWE |
| CBS followed by CMux | Front-half input or GLWE MSB bits | `CbsEvaluator`, GGSW/NGSW control |
| One-hot CBS | One padded chunk at t=2M | `one_hot_evaluator`, NLEV/NGSW selectors |

ManyLUT trades rotation resolution for output count. A three-output program reserves four lanes and returns three ciphertexts. MVB retains step-one resolution, with noise amplification from its factors. For bivariate PBS, both inputs use one secret and encoding, and the input and output codecs share a ciphertext modulus. Check the [rotation and noise conditions](../../guides/development/bootstrapping-contracts.md) and the [bivariate contract](src/lookup_table/bivariate.rs).

## Crate map and capabilities

| Family | NTT backend | Fourier backend |
| --- | --- | --- |
| [GLWE parameters and clients](../primus_tfhe_glwe/README.md) | [GLWE NTT](../primus_tfhe_glwe_ntt/README.md) | [GLWE Fourier](../primus_tfhe_glwe_fourier/README.md) |
| [NTRU parameters and clients](../primus_tfhe_ntru/README.md) | [NTRU NTT](../primus_tfhe_ntru_ntt/README.md) | [NTRU Fourier](../primus_tfhe_ntru_fourier/README.md) |

Both GLWE orders support PBS, ManyLUT, MVB and CBS. The NTRU backends also provide one-hot CBS. All four provide secret-key and LWE public-key clients. Fourier uses a native ring modulus and offers RustFFT and TFHE-FFT. Example parameters have unassessed security and failure probability. See the [parameter directory](../../guides/development/tfhe-parameters.md).

## Selecting blind rotation

Set `config.method` explicitly. `Classic` supports binary and ternary distributions, including fixed-weight binary. For direct block aggregation, select `Block` and `SecretKeyDistr::BlockBinary { block_size, occupancy }` with a logical key length divisible by the positive block width. `AtMostOne` permits an empty block and uses an independent encrypted dummy. `ExactlyOne` requires one set bit per block and omits the dummy. Classic also accepts these block distributions. NTRU Fourier Block requires u64.

When migrating a fixed-weight configuration from bucketed Sparse, select Classic, regenerate the evaluation keys and reassess noise. Switching to Block changes the secret distribution and requires its own assessment. [Block numerical contracts](../../guides/development/bootstrapping-contracts.md#classic-ternary-and-block-rotation)

## Client and server roles

Use `TfheContext::try_from_pbs_config` and `context.try_generate_keys(rng)` for PBS, ManyLUT or MVB. For CBS, use `try_from_cbs_config` and `try_generate_circuit_bootstrap_keys`. Its key bundle also serves ordinary PBS through `server.server_key()`.

The client keeps the secret keys and provides evaluation keys, ciphertexts and any encrypted ring candidates. The server compiles public LUTs and evaluates. Reuse context, keys, compiled programs and evaluators across requests. Use `as_view()` and `as_mut_view()` with the `_to` APIs to reuse outputs. Concurrent workers need separate mutable evaluators.

Raw ciphertexts carry no key or encoding identity. Use paired secrets and canonical explicit-modulus coefficients. Bind Fourier material to its original FFT table instance. See the [numerical contracts](../../guides/development/bootstrapping-contracts.md#ciphertext-domains-and-return).

### Choosing the output encoding

`PbsMessageConfig::new(t_in)` defaults to equal input and output moduli. Use `.with_output_modulus(t_out)` for a separate output domain. `from_input_bits(4)` selects 16 padded inputs with modulus 32 and a full output domain of 32.

| Operation | Program factory | Output decoder |
| --- | --- | --- |
| PBS and ManyLUT | `pbs_lookup_table_compiler()` | `pbs_decryptor` for Rounded output |
| MVB | `compile_mvb_fn(domain_len, output_count, function)` | `mvb_decryptor` for Scaled output |

Use `context.encryptor(external_secret)` or `public_encryptor(&public)` for input. Use `encrypt_padded` for front-half LUTs and `encrypt` for odd full-domain programs. `encrypt_centered` uses the centered representation and ordinary LUTs require unsigned inputs.

For an alternate message space under the same key, use `pbs_lookup_table_compiler_with_messages`, `encryptor_with_message_modulus` (or `public_encryptor_with_message_modulus`) and `pbs_decryptor_with_message_modulus`. For MVB, pair `compile_mvb_fn_with_messages` with `ring_return_decryptor` at the chosen output modulus. Before feeding an output to another PBS, check its encoding, programmed range and noise margin.

## Boolean gates

Set `PbsMessageConfig::new(4)` and use the Boolean client and evaluator factories with ordinary PBS keys. Chained gates require t=4 at both ends. GLWE also requires q=Q. [GLWE example](../primus_tfhe_glwe_ntt/examples/ntt_boolean.rs) · [NTRU example](../primus_tfhe_ntru_ntt/examples/ntru_ntt_boolean.rs)

## CBS output and consumption

Compile a custom function with `compile_cbs_fn` or `compile_cbs_slice` and bind it with `circuit_bootstrap_evaluator_with_lookup_table`. Use `circuit_bootstrap_evaluator` for identity. GLWE uses `cbs_encryptor` for either padded or MSB input. For NTRU, call `encrypt_padded` on the context's encryptor.

CBS outputs gadget-scaled ring controls. CMux requires a bit-valued function over the entire programmed domain. Prepare candidate ciphertexts with `accumulator_client(ring_secret, t_ring)`, where `t_ring` selects their independent Scaled message domain at Q. Use a common ring secret, modulus and encoding for candidates. NTRU one-hot `cmux_k_to` consumes branches 1 through M−1 and uses C0 as the default. [CBS contract](../../guides/development/bootstrapping-contracts.md#ordinary-cbs-and-consumption) · [One-hot API](../primus_tfhe_ntru/README.md#one-hot-cbs)

## Fixed-scale factorized MVB

MVB computes several functions of one padded input. Use explicit odd Q or a native ring with an even actual Scaled output scale. Budget factor amplification and, for Fourier, transform error. Use `mvb_decryptor` for the Scaled output, including numeric threshold flags. [MVB contract](../../guides/development/bootstrapping-contracts.md#factorized-mvb)

## Features and further reading

Default features are empty. `simd` forwards to arithmetic dependencies. [API sources](src/lib.rs) · [Compilation and binding errors](src/error.rs)
