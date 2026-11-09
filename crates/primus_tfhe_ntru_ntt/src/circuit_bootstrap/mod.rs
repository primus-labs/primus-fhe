//! Optional circuit-bootstrap parameters, keys, and evaluation.

mod control;
mod evaluator;
mod key;
mod one_hot;
mod one_hot_workflow;
mod workflow;
pub use one_hot_workflow::OneHotEvaluator;

pub use evaluator::CircuitBootstrapEvaluator;
pub use key::CircuitBootstrapKey;
pub use one_hot::{
    NlevSelectors, NttNgswSelectors, OneHotBootstrapError, OneHotCircuitBootstrapEvaluator,
    OneHotLookupTable, OneHotProjection,
};
pub use workflow::CbsEvaluator;
/// Shared CBS parameters specialized to this backend's modulus domain.
pub type CbsGadgetParameters<T> =
    primus_tfhe_ntru::CbsGadgetParameters<T, primus_modulus::BarrettModulus<T>>;
