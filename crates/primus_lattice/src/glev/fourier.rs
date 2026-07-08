use primus_data::RawData;

use crate::glwe::fourier::{FourierGlweIter, FourierGlweIterMut};
use num_complex::Complex64;

/// Fourier-domain GLev ciphertext — list of
/// [`crate::glwe::fourier::FourierGlwe`] per decomposition level.
///
/// ## Layout
///
/// ```text
/// |--glwe_level_0--| ... |--glwe_level_{level-1}--|
/// ```
///
/// Each level is a [`FourierGlwe`](crate::glwe::fourier::FourierGlwe) of length
/// `fourier_glwe_len`.
/// Total data length: `level * fourier_glwe_len`.
#[derive(Clone)]
pub struct FourierGlev<S>(pub S)
where
    S: RawData<Elem = Complex64>;

impl_fourier_iters!(FourierGlev);
impl_fourier_core!(FourierGlev);
impl_fourier_iter_sub!(FourierGlev, FourierGlweIter, FourierGlweIterMut, glwe);
