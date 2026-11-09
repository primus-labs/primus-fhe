//! Numerical operation choices; samplers and transforms are prepared at setup.

use crate::{CbsGadgetConfig, GadgetEncryptionConfig, PbsMessageConfig};
use primus_integer::FheUint;
use primus_ntru::SecretKeyDistr;
use primus_reduce::RingContext;
use primus_shape::PolyLength;
use primus_tfhe::{BlindRotationMethod, LweConfig, ModulusConfig};

/// Ordinary PBS/ManyLUT/MVB choices, including BR and key switching.
/// Prepared by [`PbsParameters::try_from_config`](crate::PbsParameters::try_from_config).
/// CBS reuses this domain and its KS material for subsequent LWE returns.
/// Numerical preparation does not establish security or an adequate joint noise budget.
#[derive(Debug, Clone, Copy)]
pub struct PbsConfig<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    /// External LWE secret, q and fresh-encryption noise.
    pub external_lwe: LweConfig<LM>,
    /// Ring Q and reduction representation shared by the accumulator and BSK ciphertexts.
    pub ring_modulus: ModulusConfig<M>,
    /// Ring polynomial length N shared by the accumulator and BSK ciphertexts.
    pub bsk_poly_length: PolyLength,
    /// Distribution for sampling the NTRU secret that encrypts BSK ciphertexts.
    ///
    /// BR output uses this same secret. The input LWE secret encoded by the
    /// BSK is configured separately in `external_lwe.secret_key_distr`.
    pub bsk_secret_distr: SecretKeyDistr,
    /// BSK NLev/NGSW decomposition and coefficient-unit encryption noise at Q.
    ///
    /// Ring encryption clients reuse this noise setting. Preparing the public LUT
    /// samples no encryption noise; BR lifting and controls propagate key-row noise.
    pub bsk_gadget: GadgetEncryptionConfig,
    /// Algorithm selected during material generation, not during evaluation.
    pub method: BlindRotationMethod,
    /// Independent KS decomposition and coefficient-unit row noise.
    pub key_switching: GadgetEncryptionConfig,
    /// Default input/output message moduli, selectable independently.
    pub messages: PbsMessageConfig<T>,
}

/// CBS extends the same PBS domain with trace, scheme-switch and output gadgets.
/// Direct input uses an independent LWE secret; KS is retained for downstream LWE returns.
/// Pass this configuration to [`CbsParameters::try_from_config`](crate::CbsParameters::try_from_config).
#[derive(Debug, Clone, Copy)]
pub struct CbsConfig<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    /// Common domain, algorithm and selector-input message modulus.
    /// KS also supports LWE returns after evaluating the ring output.
    pub pbs: PbsConfig<T, M, LM>,
    /// Trace, scheme-switch and output gadget decompositions.
    pub gadget: CbsGadgetConfig,
    /// Complete NGSW-only projection algorithm. Separate is the generic default;
    /// NLEV/dual use independent trace/SS regardless of projection choice.
    /// Choose before preparing parameters and generating keys; supplied material
    /// must match. Switching strategy requires reassessing the noise budget.
    pub projection: crate::NtruProjectionMethod,
}
