//! Native-torus GLWE circuit bootstrapping and its optional key material.

mod evaluator;
mod key;
mod trace;
mod workflow;
pub use trace::CbsTraceKey;

pub use evaluator::CircuitBootstrapEvaluator;
pub use key::CircuitBootstrapKey;
pub use workflow::CbsEvaluator;

/// GLWE circuit-bootstrap parameters with the native torus modulus.
///
/// Native reverse trace halves integers at each stage. Its rounding, trace key
/// switching, scheme-switch decomposition and FFT precision contribute to the
/// CBS error budget; see [`CircuitBootstrapEvaluator::try_new`].
pub type CbsGadgetParameters<T> =
    primus_tfhe_glwe::CbsGadgetParameters<T, primus_modulus::NativeModulus<T>>;
