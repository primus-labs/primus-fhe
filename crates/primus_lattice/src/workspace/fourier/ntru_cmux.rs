//! Fourier scratch storage for NTRU lifting and CMux.

use primus_decompose::DecompositionLevelCount;
use primus_fft::{Complex64, TorusFftValue};
use primus_shape::PolyLength;

use super::FourierNtruExternalProductWorkspace;

/// Shared scratch for [`FourierNlev::lift_monomial_to`](crate::nlev::FourierNlev::lift_monomial_to) and [`FourierNgsw::cmux_ternary_monomial_to`](crate::ngsw::FourierNgsw::cmux_ternary_monomial_to).
///
/// Holds one combined Fourier NLEV or NGSW and an external-product workspace. Its
/// coefficient and Fourier digit buffers first hold the integer monomial and
/// its transform; decomposition overwrites both afterwards. The output NTRU
/// supplies the coefficient difference buffer. This does not bind an FFT table.
pub struct FourierNtruCmuxWorkspace<T: TorusFftValue> {
    level_count: DecompositionLevelCount,
    pub(crate) combined_control: Box<[Complex64]>,
    pub(crate) external_product: FourierNtruExternalProductWorkspace<T>,
}

impl<T: TorusFftValue> FourierNtruCmuxWorkspace<T> {
    /// Allocates all buffers for `level_count` Fourier gadget levels.
    ///
    /// # Panics
    /// Panics if `(N / 2) * level_count`
    /// overflows `usize`.
    #[must_use]
    pub fn new(poly_length: PolyLength, level_count: DecompositionLevelCount) -> Self {
        let control_length = poly_length
            .fourier_poly_len()
            .checked_mul(level_count.get())
            .expect("Fourier gadget ciphertext length must fit in usize");
        Self {
            level_count,
            combined_control: vec![Complex64::default(); control_length].into_boxed_slice(),
            external_product: FourierNtruExternalProductWorkspace::new(poly_length),
        }
    }

    /// Returns the coefficient polynomial length shared by input and output.
    #[must_use]
    pub fn poly_length(&self) -> PolyLength {
        self.external_product.poly_length()
    }

    /// Borrows the existing external-product scratch for initialization or key switching.
    ///
    /// Its length must stay unchanged. The next lift or ternary CMUX overwrites its contents,
    /// so alternating these operations requires neither extra storage nor a reset.
    #[must_use]
    pub fn external_product_workspace(&mut self) -> &mut FourierNtruExternalProductWorkspace<T> {
        &mut self.external_product
    }

    /// Returns the level count bound to the combined-control scratch.
    #[must_use]
    pub fn level_count(&self) -> DecompositionLevelCount {
        self.level_count
    }
}
