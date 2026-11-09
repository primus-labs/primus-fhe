use num_complex::Complex64;
use primus_data::RawData;

#[allow(unused_imports)]
use super::Glev;
#[allow(unused_imports)]
use crate::glwe::{FourierGlwe, FourierGlweIter, FourierGlweIterMut};

/// Fourier-domain GLev ciphertext — list of
/// [`FourierGlwe`] per decomposition level.
///
/// ## Layout
///
/// ```text
/// |--glwe_level_0--| ... |--glwe_level_{level-1}--|
/// ```
///
/// Each level is a [`FourierGlwe`] of length
/// `fourier_glwe_len`.
/// Total data length: `level * fourier_glwe_len`.
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
pub struct FourierGlev<S>(pub S)
where
    S: RawData<Elem = Complex64>;

impl_fourier_core!(FourierGlev);

impl_fourier_iters!(FourierGlev);
impl_fourier_iter_sub!(
    FourierGlev,
    FourierGlwe,
    FourierGlweIter,
    FourierGlweIterMut,
    glwe
);

impl_fourier_basic_operation!(FourierGlev);
impl_fourier_polynomial!(FourierGlev);

impl_fourier_conversion!(Glev, FourierGlev);
