//! Experimental u64 GLWE operation configs for this Native64 Fourier backend.
//!
//! These reproduce teaching workloads recorded on 2026-10-08 at revision
//! `9a80c506`; security and decryption-failure probability are unassessed.
//! Configs contain numerical choices; parameter constructors build sampling state once.
//! Functions, lane/factor geometry and complete noise budgets belong to the operation.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_glwe::{GlweDimension, SecretKeyDistr};
use primus_lwe::LweDimension;
use primus_modulus::NativeModulus;
use primus_shape::PolyLength;

use crate::{
    BlindRotationMethod, CbsConfig, CbsGadgetConfig, DecompositionConfig, GadgetEncryptionConfig,
    LweConfig, ModulusConfig, PbsConfig, PbsMessageConfig, PbsOrder,
};

const NATIVE_Q: f64 = (1u128 << 64) as f64;
const ALPHA: f64 = 2.046_151_696_979_124e-6;
const BETA: f64 = 2.845_267_479_601_915e-15;

/// Classic Fourier PBS, n866/N2048, BR→KS, padded four-bit input and t_in=t_out=32.
pub const CLASSIC_PBS_U64: PbsConfig<u64> = dense(ModulusConfig::Native, NATIVE_Q);

/// Classic Fourier interleaved ManyLUT, n728/h32/N1024, t_in=16/t_out=8.
/// Teaching geometry is two lanes, stride two, F=(floor(x/2), [x>=5]).
pub const CLASSIC_MANY_LUT_U64: PbsConfig<u64> = fixed(
    ModulusConfig::Native,
    NATIVE_Q,
    16,
    8,
    PbsOrder::BootstrapKeyswitch,
);

/// Classic Fourier threshold MVB, n728/h32/N1024, Rounded t_in=128/Scaled t_out=2.
/// Teaching geometry is D64/k17; use `compile_mvb_fn` / `mvb_decryptor` for Scaled output.
pub const CLASSIC_THRESHOLD_MVB_U64: PbsConfig<u64> = fixed(
    ModulusConfig::Native,
    NATIVE_Q,
    128,
    2,
    PbsOrder::KeyswitchBootstrap,
);

/// Classic Fourier CBS, n800/N1024, direct small-LWE input t=8, two output levels.
/// Teaching F=[m>=2] controls CMux; the consumer chooses its ring message modulus.
pub const CLASSIC_CBS_U64: CbsConfig<u64> = circuit(ModulusConfig::Native, NATIVE_Q);

/// None keeps the maximum supported levels; the decomposition can still discard low bits.
const fn decomposition(base_log: u32) -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(base_log),
        level_count: None,
    }
}

/// Dense basic teaching profile; BR and KS retain the recorded independent noise choices.
const fn dense(modulus: ModulusConfig<NativeModulus<u64>>, q: f64) -> PbsConfig<u64> {
    let ring_noise = if BETA * q < 6.4 { 6.4 } else { BETA * q };
    PbsConfig {
        small_lwe: LweConfig {
            dimension: LweDimension::new(866),
            cipher_modulus: modulus,
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: ALPHA * q,
        },
        ring_modulus: modulus,
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(2048),
        bsk_secret_distr: SecretKeyDistr::UniformBinary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(23),
                level_count: Some(DecompositionLevelCount::new(1)),
            },
            noise_standard_deviation: ring_noise,
        },
        method: BlindRotationMethod::Classic,
        messages: PbsMessageConfig::new(32),
        key_switching: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(3),
                level_count: Some(DecompositionLevelCount::new(5)),
            },
            noise_standard_deviation: ring_noise,
        },
        order: PbsOrder::BootstrapKeyswitch,
    }
}

/// Classic fixed-weight profile for the lane and factor teaching workloads.
const fn fixed(
    modulus: ModulusConfig<NativeModulus<u64>>,
    q: f64,
    input: u64,
    output: u64,
    order: PbsOrder,
) -> PbsConfig<u64> {
    let gadget = GadgetEncryptionConfig {
        decomposition: decomposition(8),
        noise_standard_deviation: 6.4,
    };
    PbsConfig {
        small_lwe: LweConfig {
            dimension: LweDimension::new(728),
            cipher_modulus: modulus,
            secret_key_distr: SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 32 },
            noise_standard_deviation: 3.2 * q / 16384.0,
        },
        ring_modulus: modulus,
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(1024),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: gadget,
        method: BlindRotationMethod::Classic,
        key_switching: gadget,
        order,
        messages: PbsMessageConfig::new(input).with_output_modulus(output),
    }
}

/// CBS adds trace/scheme-switch gadgets to the shared BR/KS domain.
const fn circuit(modulus: ModulusConfig<NativeModulus<u64>>, q: f64) -> CbsConfig<u64> {
    let pbs = PbsConfig {
        small_lwe: LweConfig {
            dimension: LweDimension::new(800),
            cipher_modulus: modulus,
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: ALPHA * q,
        },
        ring_modulus: modulus,
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(1024),
        bsk_secret_distr: SecretKeyDistr::UniformTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: decomposition(8),
            noise_standard_deviation: 6.4,
        },
        method: BlindRotationMethod::Classic,
        key_switching: GadgetEncryptionConfig {
            decomposition: decomposition(8),
            noise_standard_deviation: 6.4,
        },
        messages: PbsMessageConfig::new(8),
        order: PbsOrder::BootstrapKeyswitch,
    };
    CbsConfig {
        fourier_trace_precision: primus_tfhe_glwe::FourierTracePrecision::Ordinary,
        input_encoding: primus_tfhe::CbsInputEncoding::Padded,
        gadget: CbsGadgetConfig {
            trace: decomposition(8),
            scheme_switch: decomposition(8),
            output: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(2)),
            },
        },
        pbs,
    }
}
