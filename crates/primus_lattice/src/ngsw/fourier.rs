mod cmux;
mod cmux_k;
mod external_product;
mod ternary;

use num_complex::Complex64;
use primus_data::RawData;

#[allow(unused_imports)]
use crate::ntru::{FourierNtru, FourierNtruIter, FourierNtruIterMut};

#[allow(unused_imports)]
use super::Ngsw;

/// A Fourier-domain [`Ngsw`] ciphertext.
///
/// Each gadget level contains one independent Fourier representation of an
/// NTRU polynomial. A coefficient polynomial of length `N` occupies `N / 2`
/// complex values.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
/// Each polynomial occupies `N / 2` complex values in the FFT table's
/// packing order. Ciphertext values use the normalized native-torus scale.
/// Levels must follow the decomposition basis's iterator order; every level
/// uses the same key, polynomial size, modulus, and representation.
#[derive(Clone)]
pub struct FourierNgsw<S>(pub S)
where
    S: RawData<Elem = Complex64>;

impl_fourier_core!(FourierNgsw);

impl_fourier_iters!(FourierNgsw);
impl_fourier_iter_sub!(
    FourierNgsw,
    FourierNtru,
    FourierNtruIter,
    FourierNtruIterMut,
    ntru
);

impl_fourier_basic_operation!(FourierNgsw);
impl_fourier_polynomial!(FourierNgsw);
impl_fourier_monomial!(FourierNgsw);

impl_fourier_conversion!(Ngsw, FourierNgsw);
