use primus_integer::FheUint;
use primus_lattice::RnsGlweSize;

mod generation;
pub(super) mod mod_down;
mod switching;

pub use switching::HybridRnsGlweKeySwitchEvaluator;

/// A GLWE key-switching key using partitioned hybrid-RNS gadget decomposition.
pub struct HybridRnsGlweKeySwitchingKey<T: FheUint> {
    key: Vec<T>,
    input_size: RnsGlweSize,
    output_size: RnsGlweSize,
    qp_size: RnsGlweSize,
    partition_moduli_count: usize,
    qp_moduli: Vec<T>,
    qp_gadget_len: usize,
}
