//! NTT scratch storage for NTRU lifting and CMux.

use primus_decompose::DecompositionLevelCount;
use primus_integer::FheUint;
use primus_shape::PolyLength;

use super::NttNtruExternalProductWorkspace;

/// Shared scratch for [`NttNlev::lift_monomial_to`](crate::nlev::NttNlev::lift_monomial_to) and [`NttNgsw::cmux_ternary_monomial_to`](crate::ngsw::NttNgsw::cmux_ternary_monomial_to).
///
/// Holds one combined NLEV or NGSW and an external-product workspace whose digit buffer
/// first holds the monomial NTT factor. The output NTRU supplies the coefficient
/// difference buffer. This binds lengths, not a modulus, basis or transform table.
pub struct NttNtruCmuxWorkspace<T: FheUint> {
    level_count: DecompositionLevelCount,
    pub(crate) combined_control: Box<[T]>,
    pub(crate) external_product: NttNtruExternalProductWorkspace<T>,
}

impl<T: FheUint> NttNtruCmuxWorkspace<T> {
    /// Allocates all buffers for `level_count` gadget levels of length `N`.
    ///
    /// # Panics
    /// Panics if `N * level_count`
    /// overflows `usize`.
    #[must_use]
    pub fn new(poly_length: PolyLength, level_count: DecompositionLevelCount) -> Self {
        let control_length = poly_length
            .get()
            .checked_mul(level_count.get())
            .expect("gadget ciphertext length must fit in usize");
        Self {
            level_count,
            combined_control: vec![T::ZERO; control_length].into_boxed_slice(),
            external_product: NttNtruExternalProductWorkspace::new(poly_length),
        }
    }

    /// Returns the polynomial length shared by input, output and control levels.
    #[must_use]
    pub fn poly_length(&self) -> PolyLength {
        self.external_product.poly_length()
    }

    /// Borrows the existing external-product scratch for initialization or key switching.
    ///
    /// Its length must stay unchanged. The next lift or ternary CMUX overwrites its contents,
    /// so alternating these operations requires neither extra storage nor a reset.
    #[must_use]
    pub fn external_product_workspace(&mut self) -> &mut NttNtruExternalProductWorkspace<T> {
        &mut self.external_product
    }

    /// Returns the level count bound to the combined-control scratch.
    #[must_use]
    pub fn level_count(&self) -> DecompositionLevelCount {
        self.level_count
    }
}
