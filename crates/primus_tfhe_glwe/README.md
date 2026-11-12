# primus_tfhe_glwe

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Shared GLWE-TFHE parameters and LWE clients. Choose [NTT](../primus_tfhe_glwe_ntt/README.md) or [Fourier](../primus_tfhe_glwe_fourier/README.md) for evaluation and complete examples.

## Experimental paired parameters

Start with a backend's `experimental::*_U64` config and prepare a context with `try_from_pbs_config` or `try_from_cbs_config`. `PbsConfig` sets the BR and KS parameters, PBS order and message domains. `CbsConfig` also sets gadget decompositions, CBS input encoding and trace precision.

Both configs include `key_switching`. Set `PbsMessageConfig::new(t_in).with_output_modulus(t_out)` for independent message moduli. Teaching configurations have unassessed security and failure probability. [Parameter conditions](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries)

## Parameters and external key domain

`small_lwe.cipher_modulus` selects the small BR input modulus q. `ring_modulus` selects Q for the accumulator and ring KS. The small dimension n must fit the flattened ring-secret length kN, and `2N` must fit the coefficient word. Both orders return under their external secret and modulus.

| PBS order | External LWE | Where KS runs |
| --- | --- | --- |
| `BootstrapKeyswitch` | Small secret, dimension n, q | After BR |
| `KeyswitchBootstrap` | Flattened ring secret, dimension kN, Q | Before BR |

Use `client.external_lwe_secret_key()` with the context's client factories and `context.allocate_lwe_ciphertext()` for the order-dependent shape. Configure BR and KS noise independently in coefficient units. Fresh external encryption in KS→BR uses the ring/BR sampler at Q. [Parameters](src/parameters.rs) · [Ciphertext domains and return](../../guides/development/bootstrapping-contracts.md#ciphertext-domains-and-return) · [Noise by key role](../../guides/development/tfhe-parameters.md#noise-by-key-role)

## Blind-rotation keys

Classic and Block support PBS, ManyLUT, MVB and CBS in both orders. For Block, set `BlindRotationMethod::Block` and `SecretKeyDistr::BlockBinary { block_size, occupancy }`. The width divides the logical small-secret length. The ring-KS public zero tail stays outside this layout. Use the Block key rustdoc to bind raw coefficient material. [Method choice](../primus_tfhe/README.md#selecting-blind-rotation) · [Block material](src/block.rs) · [Raw BR quantization](../primus_tfhe/src/rotation.rs)

## Clients and LUTs

Generate paired keys with `context.try_generate_keys(rng)`. Use `context.encryptor` or `public_encryptor` for input, then `pbs_decryptor` for Rounded PBS/ManyLUT results or `mvb_decryptor` for Scaled MVB. The context factories derive their codecs from the message configuration. A client that needs only LWE encryption or decryption can call the same factories on `PbsParameters` without loading transform tables. A public key adds noise that must fit the input budget. [Output encoding and overrides](../primus_tfhe/README.md#choosing-the-output-encoding) · [Public-key encryption](../primus_lwe/README.md#public-key-encryption)

## Boolean and CBS

Ordinary Boolean gates require q=Q, input/output t=4 and ordinary PBS material. For CBS, call `try_generate_circuit_bootstrap_keys` on a CBS context. Its bundle also supports PBS through `server.server_key()`. KS→BR uses KS to prepare the CBS input. CBS outputs gadget controls under the ring secret.

Select `CbsConfig::input_encoding` as `Padded` (inherits PBS input t) or `MsbBoolean` (t=2). Use `cbs_encryptor` or `cbs_public_encryptor` for the external input. `br_control_codec()` describes the internal small-q domain. Compile a predicate with `compile_cbs_fn` and bind it with `circuit_bootstrap_evaluator_with_lookup_table`. Use `accumulator_client(client.glwe_secret_key(), t_ring)` for Scaled CMux candidates. [CBS workflow](../primus_tfhe/README.md#cbs-output-and-consumption) · [CBS numerical contracts](../../guides/development/bootstrapping-contracts.md#ordinary-cbs-and-consumption)

`FourierTracePrecision::Ordinary` works in both backends. `Split35` affects Fourier trace only and requires the `split-trace` feature, native u64, rank one and ring-secret coefficients bounded by one. [Fourier numerical limits](../../guides/development/bootstrapping-contracts.md#glwe-fourier-error-budgets)

## Features and further reading

Default features are empty. `simd` forwards to arithmetic dependencies. Evaluation uses a concrete NTT or Fourier backend. [API sources](src/lib.rs) · [Shared operations and encoding](../primus_tfhe/README.md)
