//! Independent ownership and compatibility of classic or sparse BR controls.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::nlev::NttNlev;
use primus_ntru::SecretKeyDistr;

use super::ClassicControls;
use crate::{PbsParameters, sparse::SparseNtruBootstrappingKey};

/// Owning exact-NTT blind-rotation material, independent of LWE return and CBS keys.
/// The classic initializer and controls share the stored blind-rotation basis.
/// Classic coordinate zero holds NLEV bit controls for fused lifting; later
/// coordinates hold NGSW controls (positive/negative pairs for ternary).
/// Sparse keys instead lift with their first bucket and carry no initializer.
pub struct BlindRotationKey<T: FheUint> {
    pub(super) blind_rotation_basis: ApproxSignedBasis<T>,
    pub(super) controls: Controls<T>,
    pub(super) input_distribution: SecretKeyDistr,
}

/// Owning algorithm alternatives; sparse lifting is encoded in the first bucket.
pub(super) enum Controls<T: FheUint> {
    // First coordinate: NLEV bit(s); remaining coordinates: NGSW bit(s).
    Classic {
        initializer: NttNlev<Vec<T>>,
        data: Vec<T>,
    },
    Sparse(SparseNtruBootstrappingKey<T>),
}

// Select a borrowed algorithm once, together with the material it requires.
pub(crate) enum BootstrappingControls<'a, T: FheUint> {
    Classic(ClassicControls<'a, T>),
    Sparse(&'a SparseNtruBootstrappingKey<T>),
}

impl<T: FheUint> BlindRotationKey<T> {
    /// Returns coefficient-domain bucket selections for sparse BR material.
    #[must_use]
    pub fn sparse_bootstrapping_key(&self) -> Option<&SparseNtruBootstrappingKey<T>> {
        match &self.controls {
            Controls::Classic { .. } => None,
            Controls::Sparse(key) => Some(key),
        }
    }

    /// Borrows the classic initializer and binary/ternary control layout.
    /// Returns `None` for sparse keys, whose first bucket performs lifting.
    #[must_use]
    pub fn classic_controls(&self) -> Option<ClassicControls<'_, T>> {
        match self.bootstrapping_controls() {
            BootstrappingControls::Classic(controls) => Some(controls),
            BootstrappingControls::Sparse(_) => None,
        }
    }

    /// Pairs the chosen BR algorithm with its complete borrowed material.
    pub(crate) fn bootstrapping_controls(&self) -> BootstrappingControls<'_, T> {
        match &self.controls {
            Controls::Classic { initializer, data } => BootstrappingControls::Classic(
                ClassicControls::new(initializer, data, self.input_distribution.is_binary()),
            ),
            Controls::Sparse(key) => BootstrappingControls::Sparse(key),
        }
    }

    /// Moves independently generated bucket controls into their BR domain.
    pub(crate) fn from_sparse<LM: primus_reduce::RingContext<T>>(
        parameters: &PbsParameters<T, LM>,
        controls: SparseNtruBootstrappingKey<T>,
    ) -> Self {
        Self {
            blind_rotation_basis: parameters.blind_rotation().basis().clone(),
            controls: Controls::Sparse(controls),
            input_distribution: parameters.external_lwe().secret_key_distr(),
        }
    }

    /// Returns the declared client secret distribution.
    #[must_use]
    pub fn input_distribution(&self) -> SecretKeyDistr {
        self.input_distribution
    }

    /// Returns the common initializer/control decomposition basis.
    pub(crate) fn blind_rotation_basis(&self) -> &ApproxSignedBasis<T> {
        &self.blind_rotation_basis
    }

    /// Checks ring/basis and input layout without a return-key dependency.
    /// Bit controls do not depend on external q; input preparation binds that modulus.
    pub(crate) fn is_compatible<LM: primus_reduce::RingContext<T>>(
        &self,
        parameters: &PbsParameters<T, LM>,
    ) -> bool {
        self.input_distribution == parameters.external_lwe().secret_key_distr()
            && &self.blind_rotation_basis == parameters.blind_rotation().basis()
            && match &self.controls {
                Controls::Classic { initializer, data } => {
                    initializer.as_ref().len() == parameters.blind_rotation().nlev_len()
                        && data.len()
                            == parameters.external_lwe_dimension().get()
                                * if self.input_distribution.is_binary() {
                                    1
                                } else {
                                    2
                                }
                                * initializer.as_ref().len()
                }
                Controls::Sparse(key) => {
                    key.input_dimension() == parameters.external_lwe_dimension()
                        && key.control_len() == parameters.blind_rotation().nlev_len()
                }
            }
    }
}
