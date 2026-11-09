mod split;
pub use split::{FourierNtruSplitAutomorphism, FourierNtruSplitGadget};
mod gadget_product;

pub(crate) use gadget_product::accumulate_fourier_gadget_product;

use num_complex::Complex64;
use primus_data::RawData;

#[allow(unused_imports)]
use super::Ntru;

/// A scalar NTRU ciphertext represented by independent complex evaluations.
///
/// One negacyclic polynomial of length `N` occupies `N / 2` complex values.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Each polynomial occupies `N / 2` complex values in the FFT table's
/// packing order. Ciphertext values use the normalized native-torus scale.
#[derive(Clone)]
pub struct FourierNtru<S>(pub S)
where
    S: RawData<Elem = Complex64>;

impl_fourier_core!(FourierNtru);

impl_fourier_iters!(FourierNtru);

impl_fourier_basic_operation!(FourierNtru);
impl_fourier_polynomial!(FourierNtru);

impl_fourier_conversion!(Ntru, FourierNtru);
