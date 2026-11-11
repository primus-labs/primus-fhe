//! Experimental u64 NTRU operation configs for this Q50 NTT backend.
//!
//! These reproduce teaching workloads recorded on 2026-10-08 at revision
//! `9a80c506`; security and decryption-failure probability are unassessed.
//! Configs contain numerical choices; parameter constructors build sampling state once.
//! Functions, lane/factor geometry and complete noise budgets belong to the operation.
//! CBS and one-hot presets explicitly select PairedTrace for NGSW-only projection.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_lwe::LweDimension;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use primus_shape::PolyLength;

use crate::{
    BlindRotationMethod, CbsConfig, CbsGadgetConfig, DecompositionConfig, GadgetEncryptionConfig,
    LweConfig, ModulusConfig, PbsConfig, PbsMessageConfig,
};

const Q50: u64 = 1_125_899_906_826_241;
const EXTERNAL_Q: u64 = 1 << 24;
const ALPHA: f64 = 2.046_151_696_979_124e-6;

/// Classic NTT PBS, n866/N2048, padded four-bit input, t_in=t_out=32.
pub const CLASSIC_PBS_U64: PbsConfig<u64, PowOf2Modulus<u64>> = pbs(
    blind_rotation(
        ModulusConfig::Explicit(Q50),
        866,
        2048,
        SecretKeyDistr::UniformBinary,
        ALPHA * EXTERNAL_Q as f64,
    ),
    PbsMessageConfig::new(32),
);

/// Classic NTT ManyLUT, n728/h32/N1024, t_in=16/t_out=8, two lanes/stride two.
pub const CLASSIC_MANY_LUT_U64: PbsConfig<u64, PowOf2Modulus<u64>> =
    fixed(ModulusConfig::Explicit(Q50), 16, 8);

/// Classic NTT threshold MVB, n728/h32/N1024, Rounded t_in=128/Scaled t_out=2, D64/k17.
pub const CLASSIC_THRESHOLD_MVB_U64: PbsConfig<u64, PowOf2Modulus<u64>> =
    fixed(ModulusConfig::Explicit(Q50), 128, 2);

/// Classic NTT CBS, n800/N1024, selector t=8 and three base-256 output levels.
/// Ring CMux candidates have their own message modulus; return KS is retained for downstream use.
pub const CLASSIC_CBS_U64: CbsConfig<u64, PowOf2Modulus<u64>> =
    circuit(ModulusConfig::Explicit(Q50), SecretKeyDistr::UniformBinary);

/// Classic NTT one-hot, n800/h32/N1024, input t=8, M=4 selectors, L=3/W=4.
/// Noise is alpha*q24, distinct from n728/h32's 3276.8. Guard is -32<=e<32 in W units.
pub const CLASSIC_ONE_HOT_U64: CbsConfig<u64, PowOf2Modulus<u64>> = circuit(
    ModulusConfig::Explicit(Q50),
    SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 32 },
);

/// Maximum supported levels; low bits can remain undecomposed.
const fn decomposition(base_log: u32) -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(base_log),
        level_count: None,
    }
}

/// PBS selects messages in the shared BR/KS domain.
const fn pbs(
    blind_rotation: PbsConfig<u64, PowOf2Modulus<u64>>,
    messages: PbsMessageConfig<u64>,
) -> PbsConfig<u64, PowOf2Modulus<u64>> {
    PbsConfig {
        key_switching: GadgetEncryptionConfig {
            decomposition: decomposition(3),
            noise_standard_deviation: 3.2,
        },
        messages,
        ..blind_rotation
    }
}

/// Raw Classic q/Q and return-KS choices are shared by PBS, CBS and lookup.
const fn blind_rotation(
    modulus: ModulusConfig<BarrettModulus<u64>>,
    n: usize,
    length: usize,
    secret: SecretKeyDistr,
    noise: f64,
) -> PbsConfig<u64, PowOf2Modulus<u64>> {
    PbsConfig {
        external_lwe: LweConfig {
            dimension: LweDimension::new(n),
            cipher_modulus: ModulusConfig::Explicit(EXTERNAL_Q),
            secret_key_distr: secret,
            noise_standard_deviation: noise,
        },
        ring_modulus: modulus,
        bsk_poly_length: PolyLength::new(length),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: decomposition(8),
            noise_standard_deviation: 0.7,
        },
        method: BlindRotationMethod::Classic,
        key_switching: GadgetEncryptionConfig {
            decomposition: decomposition(3),
            noise_standard_deviation: 3.2,
        },
        messages: primus_tfhe::PbsMessageConfig::new(2),
    }
}

/// The fixed-weight profile has different fresh noise from the one-hot teaching profile.
const fn fixed(
    modulus: ModulusConfig<BarrettModulus<u64>>,
    input: u64,
    output: u64,
) -> PbsConfig<u64, PowOf2Modulus<u64>> {
    pbs(
        blind_rotation(
            modulus,
            728,
            1024,
            SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 32 },
            3.2 * EXTERNAL_Q as f64 / 16384.0,
        ),
        PbsMessageConfig::new(input).with_output_modulus(output),
    )
}

/// CBS adds three gadget decompositions and configured input; candidate t is independent.
const fn circuit(
    modulus: ModulusConfig<BarrettModulus<u64>>,
    secret: SecretKeyDistr,
) -> CbsConfig<u64, PowOf2Modulus<u64>> {
    CbsConfig {
        projection: primus_tfhe_ntru::NtruProjectionMethod::PairedTrace,
        fourier_precision: primus_tfhe_ntru::FourierCbsPrecision::ORDINARY,
        gadget: CbsGadgetConfig {
            trace: decomposition(8),
            scheme_switch: decomposition(8),
            output: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
        },
        pbs: PbsConfig {
            messages: primus_tfhe::PbsMessageConfig::new(8),
            key_switching: GadgetEncryptionConfig {
                decomposition: decomposition(3),
                noise_standard_deviation: 3.2,
            },
            ..blind_rotation(modulus, 800, 1024, secret, ALPHA * EXTERNAL_Q as f64)
        },
    }
}
