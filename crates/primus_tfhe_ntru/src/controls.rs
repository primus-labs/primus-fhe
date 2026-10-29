//! Coefficient-domain selectors for grouped NTRU blind rotation.

use std::alloc::Layout;

use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_ntru::NlevParameters;

use crate::SparseBootstrappingKeyError;

/// Coefficient controls shared by grouped NTRU blind-rotation layouts.
///
/// The grouping owner specifies the selectors and final dummy in each group.
/// The first group contains NLEV controls for public-LUT lifting; later groups
/// contain NGSW controls. Their coefficient layouts agree. The backend BR owner
/// binds the common basis and modulus; NTT residues and native-torus coefficients
/// are not interchangeable.
pub struct NtruBlindRotationControls<T: FheUint> {
    data: Vec<T>,
    input_dimension: LweDimension,
    control_len: usize,
}

impl<T: FheUint> NtruBlindRotationControls<T> {
    /// Binds complete coefficient controls to their validated logical dimension
    /// and N*L layout. Group geometry and mathematical control values belong to
    /// the caller; this checks only addressable storage and exact length.
    pub(crate) fn try_new<M: primus_reduce::RingContext<T>>(
        data: Vec<T>,
        input_dimension: LweDimension,
        control_count: usize,
        parameters: &NlevParameters<T, M>,
    ) -> Result<Self, SparseBootstrappingKeyError> {
        use SparseBootstrappingKeyError as Error;
        let control_len = parameters.nlev_len();
        let expected = control_count
            .checked_mul(control_len)
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
            control_len,
        })
    }

    /// Returns the logical external LWE dimension.
    #[must_use]
    pub fn input_dimension(&self) -> LweDimension {
        self.input_dimension
    }

    /// Returns N*L coefficient values per NLEV or NGSW control.
    #[must_use]
    pub fn control_len(&self) -> usize {
        self.control_len
    }

    /// Returns `[group][selector...,dummy][level][coefficient]` storage.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }
}
