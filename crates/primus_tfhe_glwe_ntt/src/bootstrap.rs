//! Shared input/BR bindings and reusable storage for serial PBS/CBS composition.
//! Standalone resources omit the ordinary PBS output-return stage.

use primus_glwe::{GlweCiphertext, NttGlweKeySwitchingKey, NttGlweKeySwitchingWorkspace};
use primus_integer::FheUint;
use primus_lwe::LweCiphertext;
use primus_modulus::BarrettModulus;
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;
use primus_reduce::RingContext;
use primus_tfhe::{TfheEvaluationError, rotation::RotationModulusSwitch};
use primus_tfhe_glwe::PbsOrder;

use crate::{
    Lwe, ServerKey, TfheContext,
    blind_rotation::NttGlweBlindRotationWorkspace,
    bootstrapping_key::NttGlweBootstrappingKey,
    key::BlindRotationKey,
    sparse::{SparseGlweBlindRotationWorkspace, SparseGlweBootstrappingKey},
};

/// Borrowed ring key-switch key with owned scratch and switched output.
/// The selected PBS order places this complete resource set before or after BR;
/// the lower-level key-switch workspace contains only reusable buffers.
pub(crate) struct KeySwitchingResources<'a, T: FheUint> {
    pub(crate) key: &'a NttGlweKeySwitchingKey<T>,
    pub(crate) scratch: NttGlweKeySwitchingWorkspace<T>,
    pub(crate) switched: GlweCiphertext<Vec<T>>,
}

impl<'a, T: FheUint> KeySwitchingResources<'a, T> {
    #[must_use]
    pub(crate) fn new(
        parameters: &crate::GlweKeySwitchingParameters<T>,
        key: &'a NttGlweKeySwitchingKey<T>,
    ) -> Self {
        let output = parameters.output();
        Self {
            key,
            scratch: NttGlweKeySwitchingWorkspace::new(output.glwe_size()),
            switched: GlweCiphertext::zero(output.glwe_len()),
        }
    }

    /// Switches the ring once, then extracts each requested coefficient
    /// into a compact small LWE and rounds Q→q. The checked caller supplies the
    /// exact small dimension. Equal moduli skip the entire rounding pass.
    /// Shared by input preparation (one coefficient) and PBS/ManyLUT returns.
    #[inline]
    pub(crate) fn switch_to_small<'out, Table: MonomialNttTable<ValueT = T>>(
        &mut self,
        input: GlweCiphertext<&[T]>,
        outputs: impl Iterator<Item = (usize, Lwe<&'out mut [T]>)>,
        context: crate::context::EvaluationContext<'_, T, Table>,
    ) {
        let parameters = context.parameters();
        let glwe = parameters.blind_rotation_params();
        self.key.key_switch_to(
            &input,
            &mut self.switched,
            glwe.cipher_modulus(),
            context.table(),
            &mut self.scratch,
        );
        for (index, mut output) in outputs {
            self.switched.extract_compact_lwe_at_to(
                index,
                &mut output,
                glwe.poly_length().get(),
                glwe.cipher_modulus(),
            );
            if let Some(switch) = parameters.ring_to_small_modulus_switch() {
                switch.switch_map(output.as_mut().iter_mut().map(|v| (*v, v)), |value, out| {
                    *out = value
                });
            }
        }
    }
}

/// Borrowed BR key paired with the selected algorithm's owned scratch.
/// Only classic or sparse storage is allocated; no key data is copied.
enum BlindRotationResources<'a, T: FheUint> {
    Classic {
        key: &'a NttGlweBootstrappingKey<T>,
        scratch: NttGlweBlindRotationWorkspace<T>,
    },
    Sparse {
        key: &'a SparseGlweBootstrappingKey<T, BarrettModulus<T>>,
        scratch: SparseGlweBlindRotationWorkspace<T>,
    },
}

/// KS→BR requires a compact small-LWE input; BR→KS consumes the external input directly.
enum InputPreparation<'a, T: FheUint> {
    Direct,
    Keyswitch {
        key_switching: KeySwitchingResources<'a, T>,
        small_lwe: LweCiphertext<T>,
    },
}

/// Common input preparation, blind-rotation and external-product resources.
///
/// KS→BR includes input KS and a compact small LWE. BR→KS consumes input directly
/// and includes no output KS. Ordinary [`crate::Evaluator`] owns these resources;
/// standalone CBS can prepare and borrow them without the ordinary return stage.
/// Context and keys are borrowed; accumulator and scratch buffers are owned here.
/// Serial operations can lend one instance to each other. Concurrent requests
/// need independent mutable resources and may share the immutable context/keys.
pub struct BootstrapResources<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    pub(crate) context: crate::context::EvaluationContext<'a, T, Table>,
    blind_rotation: BlindRotationResources<'a, T>,
    input: InputPreparation<'a, T>,
    ordinary_rotation: RotationModulusSwitch<T>,
    // Coefficient GLWE under the accumulator secret after either BR order.
    pub(crate) accumulator: GlweCiphertext<Vec<T>>,
}

impl<'a, T, Table> BootstrapResources<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Checks BR and supplied input KS material before allocating reusable storage.
    /// `input_key_switching_key` is required for KS→BR. BR→KS accepts `None`;
    /// a supplied key is checked but not retained, and no output KS is allocated.
    ///
    /// # Correctness
    /// Keys must use the same paired secrets and this context's NTT representation.
    /// Layout, basis and modulus checks do not establish these identities.
    pub fn try_new<LM: RingContext<T>>(
        context: &'a TfheContext<T, Table, LM>,
        blind_rotation_key: &'a BlindRotationKey<T>,
        input_key_switching_key: Option<(
            &crate::GlweKeySwitchingParameters<T>,
            &'a NttGlweKeySwitchingKey<T>,
        )>,
    ) -> Result<Self, TfheEvaluationError> {
        if let Some((key_parameters, _)) = input_key_switching_key {
            context
                .parameters()
                .evaluation()
                .check_key_switching_parameters(key_parameters)
                .map_err(|_| TfheEvaluationError::IncompatibleGlweKeySwitchingKey)?;
        }
        Self::try_from_bound_keys(context, blind_rotation_key, input_key_switching_key)
    }

    /// Binds keys after complete Context or the independent boundary paired KS parameters.
    /// Checks actual BR/KS material before allocation, without rechecking saved parameters.
    pub(crate) fn try_from_bound_keys<LM: RingContext<T>>(
        context: &'a TfheContext<T, Table, LM>,
        blind_rotation_key: &'a BlindRotationKey<T>,
        input_key_switching_key: Option<(
            &crate::GlweKeySwitchingParameters<T>,
            &'a NttGlweKeySwitchingKey<T>,
        )>,
    ) -> Result<Self, TfheEvaluationError> {
        let parameters = context.parameters();
        if !blind_rotation_key.is_compatible(parameters) {
            return Err(TfheEvaluationError::IncompatibleBlindRotationKey);
        }

        // Validate supplied material even when BR→KS does not use it for input preparation.
        // KS→BR must reject missing material before allocating any scratch.
        if let Some((key_parameters, key)) = input_key_switching_key {
            crate::key::check_bound_glwe_key_switching_key(key_parameters, key)?;
        } else if parameters.pbs_order() == PbsOrder::KeyswitchBootstrap {
            return Err(TfheEvaluationError::MissingGlweKeySwitchingKey);
        }

        Ok(Self {
            context: context.evaluation_context(),
            blind_rotation: match blind_rotation_key {
                BlindRotationKey::Classic(key) => BlindRotationResources::Classic {
                    key,
                    scratch: NttGlweBlindRotationWorkspace::new(key),
                },
                BlindRotationKey::Sparse(key) => BlindRotationResources::Sparse {
                    key,
                    scratch: SparseGlweBlindRotationWorkspace::new(key.controls()),
                },
            },
            ordinary_rotation: RotationModulusSwitch::new(
                parameters.small_lwe().cipher_modulus(),
                2 * parameters
                    .blind_rotation_params()
                    .size()
                    .glwe_size()
                    .poly_length()
                    .get(),
                1,
            ),
            input: match parameters.pbs_order() {
                PbsOrder::BootstrapKeyswitch => InputPreparation::Direct,
                PbsOrder::KeyswitchBootstrap => {
                    let (key_parameters, key) =
                        input_key_switching_key.expect("KS→BR material was checked above");
                    InputPreparation::Keyswitch {
                        key_switching: KeySwitchingResources::new(key_parameters, key),
                        small_lwe: LweCiphertext::zero(parameters.small_lwe().dimension().get()),
                    }
                }
            },
            accumulator: GlweCiphertext::zero(parameters.blind_rotation_params().glwe_len()),
        })
    }

    /// Operations retain geometry/transform state, not BR controls. Any resource
    /// instance from the same context is allowed; actual paired secrets remain
    /// the caller's responsibility, including when replacing compatible KS material.
    pub(crate) fn check_context(&self, context: crate::context::EvaluationContext<'_, T, Table>) {
        assert!(
            self.context.is_same(context),
            "bootstrap resources use a different context"
        );
    }

    /// Replaces only existing input KS material during explicit PBS recovery.
    /// The caller checked its parameters/key against this context. The switched
    /// output geometry is unchanged; BR→KS has no input KS to replace.
    pub(crate) fn rebind_input_key_switching(&mut self, key: &'a NttGlweKeySwitchingKey<T>) {
        if let InputPreparation::Keyswitch { key_switching, .. } = &mut self.input {
            key_switching.key = key;
        }
    }

    /// Temporarily bind product scratch to the requested decomposition layout.
    /// CBS and BR can use different level counts; restore the BR layout on return
    /// or unwind, retaining the same GLWE geometry and allocations.
    pub(crate) fn with_external_product<R>(
        &mut self,
        size: primus_lattice::GadgetSize,
        operation: impl FnOnce(&mut primus_lattice::workspace::NttGlweExternalProductWorkspace<T>) -> R,
    ) -> R {
        match &mut self.blind_rotation {
            BlindRotationResources::Classic { scratch, .. } => {
                scratch.with_external_product(size, operation)
            }
            BlindRotationResources::Sparse { scratch, .. } => {
                scratch.with_external_product(size, operation)
            }
        }
    }

    /// Prepare the small input for the bound order and write coefficient-domain
    /// BR under the accumulator secret. The boundary checked input/LUT geometry.
    #[inline]
    pub(crate) fn blind_rotate(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &Polynomial<Vec<T>>,
        rotation_step: usize,
    ) -> &GlweCiphertext<Vec<T>> {
        let parameters = self.context.parameters();
        let small_lwe = match &mut self.input {
            InputPreparation::Direct => input,
            InputPreparation::Keyswitch {
                key_switching: ks,
                small_lwe,
            } => {
                let glwe = parameters.blind_rotation_params();
                input.inverse_extract_glwe_to(
                    &mut self.accumulator,
                    glwe.poly_length().get(),
                    glwe.cipher_modulus(),
                );
                ks.switch_to_small(
                    self.accumulator.as_view(),
                    core::iter::once((0, small_lwe.as_mut_view())),
                    self.context,
                );
                small_lwe.as_view()
            }
        };
        // Bind this call's LUT spacing before quantizing coefficients.
        let modulus_switch = self.ordinary_rotation.with_step(rotation_step);
        match &mut self.blind_rotation {
            BlindRotationResources::Classic { key, scratch } => key
                .ntt_blind_rotate_interleaved_lookup_table_kernel_to(
                    small_lwe,
                    lookup_table.as_view(),
                    &modulus_switch,
                    self.accumulator.as_mut_view(),
                    parameters.blind_rotation_params().cipher_modulus(),
                    self.context.table(),
                    scratch,
                ),
            BlindRotationResources::Sparse { key, scratch } => scratch
                .blind_rotate_interleaved_lookup_table_kernel_to(
                    key,
                    small_lwe,
                    lookup_table.as_view(),
                    &modulus_switch,
                    self.accumulator.as_mut_view(),
                    self.context.table(),
                ),
        }
        &self.accumulator
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    LM: RingContext<T>,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Prepares common resources from a complete PBS key bundle.
    /// Selects input KS only for KS→BR; BR→KS borrows only the BR key and allocates
    /// no output-KS scratch. For independently generated material, use
    /// [`BootstrapResources::try_new`]. CBS material is bound separately by its evaluator.
    ///
    /// # Correctness
    /// Inherits [`BootstrapResources::try_new`]'s secret and transform requirements.
    pub fn bootstrap_resources_from_server_key<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<BootstrapResources<'a, T, Table>, TfheEvaluationError> {
        let key_switching = self.parameters().glwe_key_switching();
        let input_key_switching_key =
            if self.parameters().pbs_order() == PbsOrder::KeyswitchBootstrap {
                Some((key_switching, server_key.glwe_key_switching_key()))
            } else {
                None
            };
        BootstrapResources::try_from_bound_keys(
            self,
            server_key.blind_rotation_key(),
            input_key_switching_key,
        )
    }
}
