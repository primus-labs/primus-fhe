use primus_data::RawData;

use num_complex::Complex64;
use crate::glev::fourier::{FourierGlevIter, FourierGlevIterMut};

/// Fourier-domain GGSW ciphertext — matrix of [`FourierGlev`], one per row.
///
/// ## Layout
///
/// ```text
/// |--row_0--| ... |--row_k--|
/// ```
///
/// Each row is a [`FourierGlev`](crate::glev::fourier::FourierGlev) of length
/// `fourier_glev_len`.
/// Total data length: `(k + 1) * fourier_glev_len`.
#[derive(Clone)]
pub struct FourierGgsw<S>(pub S)
where
    S: RawData<Elem = Complex64>;

impl_fourier_iters!(FourierGgsw);
impl_fourier_core!(FourierGgsw);
impl_fourier_iter_sub!(
    FourierGgsw,
    FourierGlevIter,
    FourierGlevIterMut,
    glev
);
