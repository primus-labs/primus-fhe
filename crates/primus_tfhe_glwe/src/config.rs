//! Numerical operation choices; samplers and transforms are prepared at setup.

use crate::{CbsGadgetConfig, GadgetEncryptionConfig, PbsMessageConfig, PbsOrder, SecretKeyDistr};
use primus_glwe::GlweDimension;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_shape::PolyLength;
use primus_tfhe::{BlindRotationMethod, LweConfig, ModulusConfig};

/// Ordinary PBS/ManyLUT/MVB choices, including BR and key switching.
/// Prepared by [`PbsParameters::try_from_config`](crate::PbsParameters::try_from_config).
/// CBS reuses this domain and its KS material for subsequent LWE returns.
/// Numerical preparation does not establish security or an adequate joint noise budget.
#[derive(Debug, Clone, Copy)]
pub struct PbsConfig<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    /// Small BR-control LWE domain; external for BR→KS.
    pub small_lwe: LweConfig<LM>,
    /// Accumulator and evaluation-key modulus Q, independent of the BR input q.
    pub ring_modulus: ModulusConfig<M>,
    /// GLWE mask-polynomial count shared by the accumulator and BSK ciphertexts.
    pub bsk_dimension: GlweDimension,
    /// Ring polynomial length N shared by the accumulator and BSK ciphertexts.
    pub bsk_poly_length: PolyLength,
    /// Distribution for sampling the GLWE secret that encrypts BSK ciphertexts.
    ///
    /// BR output uses this same secret; the public `(0, LUT * X^(-b))`
    /// accumulator initialization needs no secret. The input LWE secret encoded
    /// by the BSK is configured separately in `small_lwe.secret_key_distr`.
    pub bsk_secret_distr: SecretKeyDistr,
    /// BSK GGSW decomposition and encryption noise in Q coefficient units.
    ///
    /// Ring encryption clients reuse this noise setting. Public GLWE accumulator
    /// initialization samples no encryption noise.
    pub bsk_gadget: GadgetEncryptionConfig,
    /// Algorithm selected when generating material; never chosen during evaluation.
    pub method: BlindRotationMethod,
    /// Independent ring-KS decomposition and row noise in Q coefficient units.
    pub key_switching: GadgetEncryptionConfig,
    /// Default input/output message moduli, selectable independently.
    pub messages: PbsMessageConfig<T>,
    /// KS placement; CBS direct input uses `BootstrapKeyswitch`.
    pub order: PbsOrder,
}

/// CBS extends the same PBS domain with trace, scheme-switch and output gadgets.
/// Direct input uses an independent LWE secret; KS is retained for downstream LWE returns.
/// Pass this configuration to [`CbsParameters::try_from_config`](crate::CbsParameters::try_from_config).
#[derive(Debug, Clone, Copy)]
pub struct CbsConfig<T: FheUint, M: RingContext<T>, LM: RingContext<T> = M> {
    /// Common domain and algorithm. Padded CBS inherits its input message modulus.
    /// KS also supports LWE returns after evaluating the ring output.
    pub pbs: PbsConfig<T, M, LM>,
    /// Trace, scheme-switch and output gadget decompositions.
    pub gadget: CbsGadgetConfig,
    /// CBS input geometry; MSB Boolean uses t=2 independently of ordinary PBS.
    pub input_encoding: primus_tfhe::CbsInputEncoding,
    /// Fourier representation of trace keys; BR and scheme switching are unaffected.
    /// Ordinary is the default choice. Split35 additionally requires the Fourier
    /// backend's `split-trace` feature; NTT configurations must use Ordinary.
    pub fourier_trace_precision: FourierTracePrecision,
}

/// Numerical representation of GLWE CBS trace keys, independent of FFT engine.
/// The selected backend checks availability when binding the prepared parameters.
/// NTT accepts Ordinary and keeps its existing NTT representation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FourierTracePrecision {
    /// Direct Fourier encryption and one spectrum per key polynomial.
    #[default]
    Ordinary,
    /// Exact coefficient keys split into unsigned low35/high29 spectra.
    /// Requires native u64, rank one and ring-secret coefficients in {-1,0,1}.
    /// Doubles trace key payload and inverse transforms; it does not certify
    /// the complete CBS noise margin or change gadget decomposition.
    Split35,
}
