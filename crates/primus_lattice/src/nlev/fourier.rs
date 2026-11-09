mod external_product;
mod external_product_sum;
mod lift;

use num_complex::Complex64;
use primus_data::RawData;

#[allow(unused_imports)]
use crate::ntru::{FourierNtru, FourierNtruIter, FourierNtruIterMut};

#[allow(unused_imports)]
use super::Nlev;

/// A Fourier-domain [`Nlev`] ciphertext.
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
pub struct FourierNlev<S>(pub S)
where
    S: RawData<Elem = Complex64>;

impl_fourier_core!(FourierNlev);

impl_fourier_iters!(FourierNlev);
impl_fourier_iter_sub!(
    FourierNlev,
    FourierNtru,
    FourierNtruIter,
    FourierNtruIterMut,
    ntru
);

impl_fourier_basic_operation!(FourierNlev);
impl_fourier_polynomial!(FourierNlev);

impl_fourier_conversion!(Nlev, FourierNlev);
