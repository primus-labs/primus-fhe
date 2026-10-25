//! Optional extension shared by native split NTRU products.
use aligned_vec::{ABox, avec};
use primus_fft::{Complex64, TorusFftValue};
use primus_shape::PolyLength;

/// Additional scratch for split products, borrowed alongside the ordinary workspace.
/// BR, trace and SS can share it serially. Neither buffer retains input between calls.
pub struct FourierNtruSplitWorkspace<T: TorusFftValue> {
    pub(crate) high_spectrum: ABox<[Complex64]>,
    pub(crate) high_product: Box<[T]>,
}
impl<T: TorusFftValue> FourierNtruSplitWorkspace<T> {
    /// Allocates one extra spectrum and one coefficient product (64 KiB at N=4096).
    #[must_use]
    pub fn new(n: PolyLength) -> Self {
        Self {
            high_spectrum: avec![Complex64::default(); n.fourier_poly_len()].into_boxed_slice(),
            high_product: vec![T::ZERO; n.get()].into_boxed_slice(),
        }
    }
}
