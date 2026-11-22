//! Deterministic small-parameter configurations shared by the workflows.

use primus_integer::FheUint;
use primus_modulus::PowOf2Modulus;
use primus_ntru::{LweDimension, SecretKeyDistr};
use primus_shape::PolyLength;
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_ntru_ntt::{
    BlindRotationMethod, CbsGadgetConfig, DecompositionConfig, GadgetEncryptionConfig, LweConfig,
    ModulusConfig, PbsConfig, PbsMessageConfig,
};

fn decomposition() -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: None,
    }
}

/// The CBS cases share base 16 and vary only the requested output levels.
pub(super) fn cbs_gadget(level_count: Option<DecompositionLevelCount>) -> CbsGadgetConfig {
    CbsGadgetConfig {
        trace: decomposition(),
        scheme_switch: decomposition(),
        output: DecompositionConfig {
            level_count,
            ..decomposition()
        },
    }
}

/// Keep rounding and transform error far below the test message spacing.
/// Default to a fixed-weight Classic input. Block fixtures select their own
/// distribution and other Classic fixtures exercise binary or ternary inputs.
pub(super) fn config<T: FheUint>(method: BlindRotationMethod) -> PbsConfig<T, PowOf2Modulus<T>> {
    let modulus = ModulusConfig::Explicit(T::as_from(if T::BITS == 32 {
        998_244_353u64
    } else {
        1_125_899_906_826_241u64
    }));
    // The independent external LWE secret may have even weight.
    let secret = SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 2 };
    PbsConfig {
        external_lwe: LweConfig {
            dimension: LweDimension::new(8),
            cipher_modulus: ModulusConfig::Explicit(T::as_from(1u32 << 24)),
            secret_key_distr: secret,
            noise_standard_deviation: 1.0,
        },
        ring_modulus: modulus,
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        method,
        bsk_poly_length: PolyLength::new(128),
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: decomposition(),
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: decomposition(),
            noise_standard_deviation: 1.0,
        },
        messages: PbsMessageConfig::new(T::as_from(8)),
    }
}
