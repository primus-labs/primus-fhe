//! Independent ownership and compatibility of Classic and Block BR controls.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::nlev::NttNlev;
use primus_ntru::SecretKeyDistr;

use super::ClassicControls;
use crate::{PbsParameters, block::BlockNtruBootstrappingKey};

/// Owning exact-NTT blind-rotation material, independent of LWE return and CBS keys.
/// The classic initializer and controls share the stored blind-rotation basis.
/// Classic coordinate zero holds NLEV bit controls for fused lifting; later
/// coordinates hold NGSW controls (positive/negative pairs for ternary).
/// Block keys lift with their first block and carry no initializer.
pub struct BlindRotationKey<T: FheUint> {
    pub(super) blind_rotation_basis: ApproxSignedBasis<T>,
    pub(super) controls: Controls<T>,
    pub(super) input_distribution: SecretKeyDistr,
}

/// Owning algorithm alternatives; Block lifting is encoded in the first block.
pub(super) enum Controls<T: FheUint> {
    // First coordinate: NLEV bit(s); remaining coordinates: NGSW bit(s).
    Classic {
        initializer: NttNlev<Vec<T>>,
        data: Vec<T>,
    },
    Block(BlockNtruBootstrappingKey<T>),
}

// Select a borrowed algorithm once, together with the material it requires.
pub(crate) enum BootstrappingControls<'a, T: FheUint> {
    Classic(ClassicControls<'a, T>),
    Block(&'a BlockNtruBootstrappingKey<T>),
}

impl<T: FheUint> BlindRotationKey<T> {
    /// Returns contiguous coefficient controls for direct block BR material.
    #[must_use]
    pub fn block_bootstrapping_key(&self) -> Option<&BlockNtruBootstrappingKey<T>> {
        match &self.controls {
            Controls::Block(key) => Some(key),
            Controls::Classic { .. } => None,
        }
    }

    /// Borrows the classic initializer and binary/ternary control layout.
    /// Returns `None` for Block keys, whose first block performs lifting.
    #[must_use]
    pub fn classic_controls(&self) -> Option<ClassicControls<'_, T>> {
        match self.bootstrapping_controls() {
            BootstrappingControls::Classic(controls) => Some(controls),
            BootstrappingControls::Block(_) => None,
        }
    }

    /// Pairs the chosen BR algorithm with its complete borrowed material.
    pub(crate) fn bootstrapping_controls(&self) -> BootstrappingControls<'_, T> {
        match &self.controls {
            Controls::Classic { initializer, data } => BootstrappingControls::Classic(
                ClassicControls::new(initializer, data, self.input_distribution.is_binary()),
            ),
            Controls::Block(key) => BootstrappingControls::Block(key),
        }
    }

    /// Moves independently generated block controls into their BR domain.
    pub(crate) fn from_block<LM: primus_reduce::RingContext<T>>(
        parameters: &PbsParameters<T, LM>,
        controls: BlockNtruBootstrappingKey<T>,
    ) -> Self {
        Self {
            blind_rotation_basis: parameters.blind_rotation().basis().clone(),
            controls: Controls::Block(controls),
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
                Controls::Block(key) => {
                    self.input_distribution
                        == SecretKeyDistr::BlockBinary {
                            block_size: key.block_size(),
                            occupancy: key.occupancy(),
                        }
                        && key.input_dimension() == parameters.external_lwe_dimension()
                        && key.control_len() == parameters.blind_rotation().nlev_len()
                }
            }
    }
}
