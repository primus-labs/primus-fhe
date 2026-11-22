# primus_tfhe_ntru

English | [简体中文](README.zh_CN.md)

> [!WARNING]
> This crate is part of the experimental [Primus FHE](../../README.md) workspace. Its API and numerical contracts are unstable and may change incompatibly at any time.

Shared NTRU-TFHE parameters and external LWE clients. Choose [NTT](../primus_tfhe_ntru_ntt/README.md) or [Fourier](../primus_tfhe_ntru_fourier/README.md) for evaluation and complete examples.

## Experimental paired parameters

Start with a backend's `experimental::*_U64` config. Use `TfheContext::try_from_pbs_config` for PBS, ManyLUT and MVB, and `try_from_cbs_config` for CBS and one-hot. Both configs include return `key_switching`. Use `PbsMessageConfig::new(t_in).with_output_modulus(t_out)` to choose independent input and output message moduli. Teaching configurations have unassessed security and failure probability. [Parameter conditions](../../guides/development/tfhe-parameters.md#scope-of-paired-parameter-entries)

## Parameters and key domains

`external_lwe` selects the external secret s, dimension n and modulus q. `ring_modulus`, `bsk_poly_length` and `bsk_secret_distr` select the accumulator ring and secret f at Q. n and N are independent, and `2N` must fit the coefficient word. Only f needs NTRU invertibility and Fourier inverse-stability screening. Complete key generation also requires the signed magnitudes of f's coefficients to fit below explicit q.

The external, BSK and return KS noises use coefficient units at their respective moduli. BSK noise also sets ring-candidate, trace and scheme-switch encryption noise. Configure BR and return KS independently. [Parameter API](src/parameters.rs) · [Noise by key role](../../guides/development/tfhe-parameters.md#noise-by-key-role)

## Blind-rotation methods

Classic supports binary and ternary external secrets, including fixed-weight binary. For direct block aggregation, set `BlindRotationMethod::Block` with `SecretKeyDistr::BlockBinary { block_size, occupancy }`. The first block uses NLEV to lift the public LUT, including when the first block is empty or its rotation is zero. Later blocks use NGSW. Fourier Block requires u64 and supports ordinary and split BR. [Block material](src/block.rs) · [First lift](../../guides/development/bootstrapping-contracts.md#ntru-first-lifting)

## Clients and LUTs

Generate paired keys with `context.try_generate_keys(rng)` and pass `client.external_lwe_secret_key()` to the client factories. PBS/ManyLUT use Rounded output and `pbs_decryptor`. MVB uses Scaled output and `mvb_decryptor`. Use `encrypt_padded` for front-half programs and `encrypt` for odd full-domain programs. A client that needs only LWE encryption or decryption can call the same factories on `PbsParameters` without loading transform tables. `public_encryptor` uses a public LWE key at q and requires a public-key input noise budget. [Output encoding and overrides](../primus_tfhe/README.md#choosing-the-output-encoding) · [Public-key encryption](../primus_lwe/README.md#public-key-encryption)

## CBS and examples

Generate CBS material with `try_generate_circuit_bootstrap_keys`. Its bundle also supports ordinary PBS through `server.server_key()`. Use a padded input, compile the function with `compile_cbs_fn` and bind it with `circuit_bootstrap_evaluator_with_lookup_table`. Output NGSW uses gadget scaling under f. For CMux, choose a bit-valued function and encrypt the candidates with `accumulator_client(client.accumulator_ntru_secret_key(), t_ring)` at an independent Scaled message modulus. [CBS workflow](../primus_tfhe/README.md#cbs-output-and-consumption)

Choose projection and Fourier precision before preparing the context and keys. Fused strategies affect NGSW output, and NLEV and dual outputs use separate trace and scheme switching at their configured precision. Same-secret scheme switching requires a justified key-dependent-message assumption. [Projection and precision matrix](../../guides/development/bootstrapping-contracts.md#ntru-cbs-precision-and-projection-support) · [Same-secret scheme switching](../primus_ntru/README.md#same-secret-scheme-switching)

## One-hot CBS

Use `context.one_hot_evaluator(&server)` with the same CBS bundle. For M a power of two with M≥2, select input modulus t=2M and encrypt a value in `0..M` with `encrypt_padded`. With L output levels and W=next_power_of_two(L), require 2MW≤N and a sufficient phase margin. [Selection geometry](../../guides/development/bootstrapping-contracts.md#one-hot-cbs)

Use `allocate_nonzero_ngsw_output` and `one_hot_nonzero_ngsw_to` for `cmux_k_to`. It consumes selectors 1 through M−1 and defaults to candidate C0. The NLEV-only and dual APIs return coefficient-form NLEV, which must be transformed before a public-polynomial product. `selector(r)` uses the mathematical branch number. [Selector layouts](src/one_hot/selectors.rs)

Block supports pairing through `new_pair_workspace` and `with_pair`. Consume each selector view inside the callback. Classic and an odd final input use the single-input methods. For public lifting without a preceding CMux layer (c=d), call `try_generate_public_lift_key` for independent `NLEV[1]` when using Block or split BR. Fourier uses ordinary lift material for this product. [Block key contract](src/block.rs) · [NTT key generator](../primus_tfhe_ntru_ntt/src/key.rs) · [Fourier key generator](../primus_tfhe_ntru_fourier/src/key.rs)

## NTRU→LWE returns

PBS evaluators return under s at q after coefficient-wise Q→q rounding, phase extraction and LWE KS. Return rescales the existing phase, so budget any mismatch in encoding scales. Use the re-exported `LweReturnEvaluator` for independent coefficient-domain ring results and `LweReturnBatchWorkspace` for batches. [Return API and numerical contract](../primus_ntru/README.md#independent-lwe-return) · [Ciphertext domains](../../guides/development/bootstrapping-contracts.md#ciphertext-domains-and-return)

## Features and further reading

Default features are empty. `simd` forwards to arithmetic dependencies. Evaluation uses a concrete NTT or Fourier backend. [API sources](src/lib.rs) · [Shared operations and encoding](../primus_tfhe/README.md)
