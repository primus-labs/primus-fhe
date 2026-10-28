//! Experimental u64 GLWE operation configs for this Q50 NTT backend.
//!
//! These are teaching workloads, not certified security or failure-probability
//! presets. Classic CBS uses independently sampled binary secrets at n866/N2048;
//! other entries retain their earlier teaching choices.
//! Configs contain numerical choices; parameter constructors build sampling state once.
//! Functions, lane/factor geometry and complete noise budgets belong to the operation.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_glwe::{GlweDimension, SecretKeyDistr};
use primus_lwe::LweDimension;
use primus_modulus::BarrettModulus;
use primus_shape::PolyLength;

use crate::{
    BlindRotationMethod, CbsConfig, CbsGadgetConfig, DecompositionConfig, GadgetEncryptionConfig,
    LweConfig, ModulusConfig, PbsConfig, PbsMessageConfig, PbsOrder,
};

const Q50: u64 = 1_125_899_906_826_241;
const ALPHA: f64 = 2.046_151_696_979_124e-6;
const BETA: f64 = 2.845_267_479_601_915e-15;
const SPARSE: BlindRotationMethod = BlindRotationMethod::Sparse {
    copy_count: 3,
    bucket_count: 64,
};

/// Classic NTT PBS, n866/N2048, BR→KS, padded four-bit input and t_in=t_out=32.
pub const CLASSIC_PBS_U64: PbsConfig<u64> = dense(ModulusConfig::Explicit(Q50), Q50 as f64);

/// Sparse NTT PBS, n728/h32/N1024, three copies/64 buckets, t_in=t_out=32.
pub const SPARSE_PBS_U64: PbsConfig<u64> = fixed(
    ModulusConfig::Explicit(Q50),
    Q50 as f64,
    SPARSE,
    32,
    32,
    PbsOrder::BootstrapKeyswitch,
);

/// Classic NTT interleaved ManyLUT, n728/h32/N1024, t_in=16/t_out=8.
/// Teaching geometry is two lanes, stride two, F=(floor(x/2), [x>=5]).
pub const CLASSIC_MANY_LUT_U64: PbsConfig<u64> = fixed(
    ModulusConfig::Explicit(Q50),
    Q50 as f64,
    BlindRotationMethod::Classic,
    16,
    8,
    PbsOrder::BootstrapKeyswitch,
);

/// Classic NTT threshold MVB, n728/h32/N1024, Rounded t_in=128/Scaled t_out=2.
/// Teaching geometry is D64/k17; use `compile_mvb_fn` / `mvb_decryptor` for Scaled output.
pub const CLASSIC_THRESHOLD_MVB_U64: PbsConfig<u64> = fixed(
    ModulusConfig::Explicit(Q50),
    Q50 as f64,
    BlindRotationMethod::Classic,
    128,
    2,
    PbsOrder::KeyswitchBootstrap,
);

/// Classic NTT CBS, n866/N2048, independent binary secrets, padded input t=8.
///
/// BR uses (log₂B,L)=(15,2), trace/SS (12,3), output (8,2), return KS (3,5).
/// Fresh and KS rows share the small-LWE deviation; BR/trace/SS rows use 6.4.
/// The tested consumer is F=[m>=2] followed by CMux at Scaled t_ring=8 and an
/// LWE return. Conditional model screening is not a complete security/DFR claim.
pub const CLASSIC_CBS_U64: CbsConfig<u64> =
    circuit(ModulusConfig::Explicit(Q50), Q50 as f64, false);

/// Sparse NTT CBS, n728/h32/N1024, input t=8, direct small-LWE input and retained return KS.
pub const SPARSE_CBS_U64: CbsConfig<u64> = circuit(ModulusConfig::Explicit(Q50), Q50 as f64, true);

/// None keeps the maximum supported levels; the decomposition can still discard low bits.
const fn decomposition(base_log: u32) -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(base_log),
        level_count: None,
    }
}

/// Dense basic teaching profile; BR and KS retain the recorded independent noise choices.
const fn dense(modulus: ModulusConfig<BarrettModulus<u64>>, q: f64) -> PbsConfig<u64> {
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

/// Fixed-weight numeric profile shared by the sparse, lane and factor teaching workloads.
const fn fixed(
    modulus: ModulusConfig<BarrettModulus<u64>>,
    q: f64,
    algorithm: BlindRotationMethod,
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
        method: algorithm,
        key_switching: gadget,
        order,
        messages: PbsMessageConfig::new(input).with_output_modulus(output),
    }
}

/// CBS adds trace/scheme-switch gadgets to the shared BR/KS domain.
const fn circuit(
    modulus: ModulusConfig<BarrettModulus<u64>>,
    q: f64,
    sparse: bool,
) -> CbsConfig<u64> {
    let blind_rotation = if sparse {
        fixed(modulus, q, SPARSE, 8, 8, PbsOrder::BootstrapKeyswitch)
    } else {
        let mut pbs = dense(modulus, q);
        pbs.bsk_gadget.decomposition = DecompositionConfig {
            log_basis: DecompositionBaseLog::new(15),
            level_count: Some(DecompositionLevelCount::new(2)),
        };
        // The return target has n random coefficients and a public zero tail.
        // Its row noise is chosen independently from the BSK's ring noise.
        pbs.key_switching.noise_standard_deviation = pbs.small_lwe.noise_standard_deviation;
        pbs
    };
    let projection = if sparse {
        decomposition(8)
    } else {
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(12),
            level_count: Some(DecompositionLevelCount::new(3)),
        }
    };
    CbsConfig {
        fourier_trace_precision: primus_tfhe_glwe::FourierTracePrecision::Ordinary,
        input_encoding: primus_tfhe::CbsInputEncoding::Padded,
        gadget: CbsGadgetConfig {
            trace: projection,
            scheme_switch: projection,
            output: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(2)),
            },
        },
        pbs: PbsConfig {
            messages: primus_tfhe::PbsMessageConfig::new(8),
            order: PbsOrder::BootstrapKeyswitch,
            ..blind_rotation
        },
    }
}
