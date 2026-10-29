//! Coefficient controls and common numerical layout for grouped blind rotation.

use std::alloc::Layout;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::GgswParameters;
use primus_integer::FheUint;
use primus_lattice::{GadgetSize, LweDimension};
use primus_reduce::{Modulus, RingContext};

/// Allocation/layout failures shared by coefficient control owners. Owners map
/// these into their public error so block material does not expose bucket terms.
pub(crate) enum BlindRotationControlsError {
    RotationDomainTooLarge,
    StorageSizeOverflow,
    StorageLengthMismatch { expected: usize, actual: usize },
}

/// Coefficient-domain GGSW controls and their common blind-rotation layout.
///
/// The owning key determines how selectors and any independent dummy controls are
/// grouped. This storage retains no public bucket map or secret assignment.
/// NTT uses explicit canonical residues and Fourier uses exact native-torus
/// coefficients; their representations are not interchangeable.
pub struct GlweBlindRotationControls<T: FheUint, M: RingContext<T>> {
    data: Vec<T>,
    input_dimension: LweDimension,
    modulus: M,
    input_modulus: Option<T>,
    size: GadgetSize,
    basis: ApproxSignedBasis<T>,
}

impl<T: FheUint, M: RingContext<T>> GlweBlindRotationControls<T, M> {
    /// Bind the already encrypted rows to their common shape, with no copying,
    /// transformation or coefficient scan. The owner validates group geometry.
    pub(crate) fn try_new<LM: Modulus<ValueT = T>>(
        data: Vec<T>,
        input_dimension: LweDimension,
        control_count: usize,
        parameters: &GgswParameters<T, M>,
        input_modulus: LM,
    ) -> Result<Self, BlindRotationControlsError> {
        use BlindRotationControlsError as Error;
        let size = parameters.size();
        let two_n = 2 * size.glwe_size().poly_length().get();
        if T::try_from(two_n).is_err() {
            return Err(Error::RotationDomainTooLarge);
        }
        let expected = control_count
            .checked_mul(size.ggsw_len())
            .ok_or(Error::StorageSizeOverflow)?;
        Layout::array::<T>(expected).map_err(|_| Error::StorageSizeOverflow)?;
        if data.len() != expected {
            return Err(Error::StorageLengthMismatch {
                expected,
                actual: data.len(),
            });
        }
        Ok(Self {
            data,
            input_dimension,
            modulus: parameters.cipher_modulus(),
            input_modulus: input_modulus.explicit_value(),
            size,
            basis: parameters.basis().clone(),
        })
    }

    /// Returns the logical LWE input dimension, excluding ring-KS zero padding.
    #[must_use]
    #[inline]
    pub fn input_dimension(&self) -> LweDimension {
        self.input_dimension
    }

    /// Returns the explicit input modulus q, or `None` for the native torus.
    #[must_use]
    #[inline]
    pub fn input_modulus_value(&self) -> Option<T> {
        self.input_modulus
    }

    /// Returns the reducer for accumulator coefficients and gadget rows at Q.
    #[must_use]
    #[inline]
    pub fn ring_modulus(&self) -> M {
        self.modulus
    }

    /// Returns the explicit accumulator modulus, or `None` for the native torus.
    #[must_use]
    #[inline]
    pub fn cipher_modulus(&self) -> Option<T> {
        self.modulus.explicit_value()
    }

    /// Returns the GGSW layout shared by all selections and dummies.
    #[must_use]
    #[inline]
    pub fn size(&self) -> GadgetSize {
        self.size
    }

    /// Returns the decomposition basis, including its level order.
    #[must_use]
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns coefficient controls in their owning key's group order.
    /// Every control uses `[row][level][component][coefficient]` order.
    #[must_use]
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }
}
