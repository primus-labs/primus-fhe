//! Optional circuit-bootstrap parameters, keys, and evaluation.

mod evaluator;
mod key;
mod workflow;

pub use evaluator::CircuitBootstrapEvaluator;
pub use key::CircuitBootstrapKey;
pub use workflow::CbsEvaluator;

/// GLWE circuit-bootstrap parameters with a Barrett ciphertext modulus.
///
/// Matching parameters do not establish secret or NTT representation identity;
/// see [`CircuitBootstrapEvaluator::try_new`].
pub type CbsGadgetParameters<T> =
    primus_tfhe_glwe::CbsGadgetParameters<T, primus_modulus::BarrettModulus<T>>;
