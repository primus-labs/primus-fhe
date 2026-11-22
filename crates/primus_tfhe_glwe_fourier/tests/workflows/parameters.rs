//! Small deterministic parameter fixtures shared by these workflows.

use primus_fft::TorusFftValue;
use primus_glwe::{BlockOccupancy, GlweDimension, SecretKeyDistr};
use primus_lwe::LweDimension;
use primus_modulus::PowOf2Modulus;
use primus_shape::PolyLength;
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_glwe_fourier::{
    BlindRotationMethod, CbsGadgetConfig, DecompositionConfig, GadgetEncryptionConfig, LweConfig,
    ModulusConfig, PbsConfig, PbsMessageConfig, PbsOrder,
};

pub(super) fn decomposition() -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: None,
    }
}

pub(super) fn cbs_gadget() -> CbsGadgetConfig {
    let mut output = decomposition();
    output.level_count = Some(DecompositionLevelCount::new(3));
    CbsGadgetConfig {
        trace: decomposition(),
        scheme_switch: decomposition(),
        output,
    }
}

/// Keep rounding and transform error far below the test message spacing.
/// Classic defaults to fixed weight. Block uses two non-power-of-two blocks.
pub(super) fn config<T: TorusFftValue>(method: BlindRotationMethod) -> PbsConfig<T> {
    let modulus = ModulusConfig::Native;
    let secret = if method == BlindRotationMethod::Block {
        SecretKeyDistr::BlockBinary {
            block_size: 3,
            occupancy: BlockOccupancy::AtMostOne,
        }
    } else {
        SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 3 }
    };
    PbsConfig {
        small_lwe: LweConfig {
            dimension: LweDimension::new(if method == BlindRotationMethod::Block {
                6
            } else {
                8
            }),
            cipher_modulus: modulus,
            secret_key_distr: secret,
            noise_standard_deviation: 1.0,
        },
        ring_modulus: modulus,
        bsk_dimension: GlweDimension::new(2),
        bsk_secret_distr: SecretKeyDistr::UniformTernary,
        method,
        order: PbsOrder::BootstrapKeyswitch,
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

/// q uses a power-of-two reducer independently of the accumulator representation.
/// Keep ring secret ternary/rank two to exercise signed padding and extraction.
pub(super) fn two_domain_config<T: TorusFftValue>(
    method: BlindRotationMethod,
    order: PbsOrder,
) -> PbsConfig<T, PowOf2Modulus<T>> {
    let base = config::<T>(method);
    PbsConfig {
        small_lwe: LweConfig {
            cipher_modulus: ModulusConfig::Explicit(T::as_from(1024)),
            dimension: base.small_lwe.dimension,
            secret_key_distr: if method == BlindRotationMethod::Classic {
                SecretKeyDistr::UniformTernary
            } else {
                base.small_lwe.secret_key_distr
            },
            noise_standard_deviation: base.small_lwe.noise_standard_deviation,
        },
        ring_modulus: base.ring_modulus,
        bsk_dimension: base.bsk_dimension,
        bsk_poly_length: base.bsk_poly_length,
        bsk_secret_distr: base.bsk_secret_distr,
        bsk_gadget: base.bsk_gadget,
        method,
        key_switching: base.key_switching,
        messages: base.messages,
        order,
    }
}
