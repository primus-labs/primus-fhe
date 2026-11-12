use primus_fft::{FftTable, TorusFftValue};
use primus_glwe::{FourierGlweKeySwitchingKey, GlweCiphertext};
use primus_lwe::LweCiphertext;
use primus_reduce::{Modulus, RingContext};
use primus_tfhe::{
    InterleavedLookupTable, LookupTable, ProgrammableBootstrap, ProgrammableBootstrapInterleaved,
};

use crate::{
    GlweKeySwitchingParameters, Lwe, ServerKey, TfheContext,
    bootstrap::{BootstrapResources, KeySwitchingResources},
    error::TfheEvaluationError,
    key::BlindRotationKey,
};

/// Reusable Fourier programmable bootstrap with common resources and a complete return stage.
/// BR→KS owns output KS; KS→BR uses the common input KS and extracts directly.
/// CBS borrows common resources; MVB takes ownership of this evaluator.
pub struct Evaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    pub(crate) resources: BootstrapResources<'a, T, Table>,
    return_key_switching: Option<KeySwitchingResources<'a, T>>, // None: extraction after input KS.
}

impl<T, Table> ProgrammableBootstrap<T> for Evaluator<'_, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    #[inline]
    fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &LookupTable<T>,
        output: Lwe<&mut [T]>,
    ) {
        Evaluator::apply_lookup_table_to(self, input, lookup_table, output)
    }
}

impl<T, Table> ProgrammableBootstrapInterleaved<T> for Evaluator<'_, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    #[inline]
    fn apply_interleaved_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &InterleavedLookupTable<T>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        Evaluator::apply_interleaved_lookup_table_to(self, input, lookup_table, outputs)
    }
}

impl<'a, T, Table> Evaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Binds independent BR and ring KS material for either PBS order.
    /// Checks layouts, input distribution and decomposition bases/moduli once.
    ///
    /// # Correctness
    /// Materials must use the same paired small/accumulator secrets and context
    /// transform representation; parameter checks cannot establish their identity.
    /// Inherits [`TfheContext::evaluator`]'s transform requirements.
    pub fn try_from_parts<LM: RingContext<T>>(
        context: &'a TfheContext<T, Table, LM>,
        key_switching: &GlweKeySwitchingParameters<T>,
        blind_rotation_key: &'a BlindRotationKey<T>,
        key_switching_key: &'a FourierGlweKeySwitchingKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        let resources = BootstrapResources::try_new(
            context,
            blind_rotation_key,
            Some((key_switching, key_switching_key)),
        )?;
        Ok(Self::from_resources(resources, key_switching_key))
    }

    /// Select the return once after the input/BR material has been bound.
    /// KS→BR already owns its input KS; constructing the return never rebinds it.
    #[must_use]
    fn from_resources(
        resources: BootstrapResources<'a, T, Table>,
        key: &'a FourierGlweKeySwitchingKey<T>,
    ) -> Self {
        let return_key_switching = match resources.context.parameters().pbs_order() {
            crate::PbsOrder::BootstrapKeyswitch => Some(KeySwitchingResources::new(key)),
            crate::PbsOrder::KeyswitchBootstrap => None,
        };
        Self {
            resources,
            return_key_switching,
        }
    }

    /// Borrows common resources to prepare CBS operation state.
    #[must_use]
    pub fn bootstrap_resources(&self) -> &BootstrapResources<'a, T, Table> {
        &self.resources
    }

    /// Lends common input/BR/EP resources while retaining the ordinary return stage.
    ///
    /// # Correctness
    /// Preserve the context and paired-secret binding: retained return material
    /// and buffers were prepared for it. Preserve the FFT table instance as well;
    /// this borrow does not rebind the evaluator.
    #[must_use]
    pub fn bootstrap_resources_mut(&mut self) -> &mut BootstrapResources<'a, T, Table> {
        &mut self.resources
    }

    /// Adds the configured return stage to standalone CBS resources.
    /// Reuses BR/transform storage; BR→KS allocates output KS scratch, while
    /// KS→BR reuses input KS scratch and binds the supplied bundle's KS key.
    ///
    /// # Correctness
    /// The bundle must use the resources' paired secrets and transform representation.
    /// Layout and modulus checks do not establish secret or transform identity.
    pub fn try_from_resources(
        mut resources: BootstrapResources<'a, T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        let key_switching = resources.context.parameters().glwe_key_switching();
        let key = server_key.glwe_key_switching_key();
        crate::key::check_bound_glwe_key_switching_key(key_switching, key)?;
        resources.rebind_input_key_switching(key);
        Ok(Self::from_resources(resources, key))
    }

    /// Returns one coefficient of a coefficient-domain accumulator ciphertext.
    /// BR→KS performs ring KS, compact extraction, then Q→q, returning under
    /// the small secret. KS→BR extracts directly under the full accumulator
    /// secret at Q. Reuses this evaluator's buffers without copying the input.
    ///
    /// # Correctness
    /// Input must use the bound accumulator secret, modulus and canonical residues.
    /// Compact extraction relies on the KS target's actual zero-padded secret
    /// suffix; see [`GlweCiphertext::extract_compact_lwe_at_to`].
    /// Return does not re-encode the phase. For Scaled ring messages use
    /// [`TfheContext::ring_return_decryptor`] with their original message modulus,
    /// budgeting prior ring error, KS error and any Q→q rounding together.
    ///
    /// # Panics
    /// Rejects an invalid index or input/output length before writes.
    pub fn return_ring_at_to(
        &mut self,
        input: GlweCiphertext<&[T]>,
        index: usize,
        mut output: Lwe<&mut [T]>,
    ) {
        let parameters = self.resources.context.parameters();
        let glwe = parameters.blind_rotation_params();
        assert!(
            index < glwe.poly_length().get(),
            "ring extraction index is out of range"
        );
        assert_eq!(
            input.as_ref().len(),
            glwe.glwe_len(),
            "ring input ciphertext length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            parameters.external_lwe_dimension().ciphertext_len(),
            "returned LWE ciphertext length mismatch"
        );
        match &mut self.return_key_switching {
            Some(ks) => ks.switch_to_small(
                input,
                core::iter::once((index, output)),
                self.resources.context,
                &mut self.resources.fft,
            ),
            None => input.extract_compact_lwe_at_to(
                index,
                &mut output,
                glwe.poly_length().get(),
                glwe.cipher_modulus(),
            ),
        }
    }

    /// Applies a compiled lookup table and returns a refreshed ciphertext in
    /// the external LWE dimension selected by the PBS order.
    ///
    /// Inherits [`ProgrammableBootstrap::apply_lookup_table_to`]'s input encoding,
    /// key, noise and output-scale requirements.
    ///
    /// # Panics
    ///
    /// Panics on an incompatible input dimension or LUT encoding/moduli/length.
    #[must_use]
    pub fn apply_lookup_table(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &LookupTable<T>,
    ) -> LweCiphertext<T> {
        let dimension = self.resources.context.parameters().external_lwe_dimension();
        let mut output = LweCiphertext::zero(dimension.get());
        self.apply_lookup_table_to(input, lookup_table, output.as_mut_view());
        output
    }

    /// Applies a compiled lookup table into an existing ciphertext allocation.
    ///
    /// Inherits [`ProgrammableBootstrap::apply_lookup_table_to`]'s input encoding,
    /// key, noise and output-scale requirements.
    ///
    /// # Panics
    ///
    /// Panics before output writes on incompatible LUT encoding/moduli/length
    /// or ciphertext dimensions.
    pub fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &LookupTable<T>,
        output: Lwe<&mut [T]>,
    ) {
        let parameters = self.resources.context.parameters();
        assert!(
            lookup_table.is_compatible_with_ciphertext_domain(
                parameters.blind_rotation_params().poly_length(),
                parameters.small_modulus_value(),
                parameters.ring_modulus().explicit_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let expected_dimension = parameters.external_lwe_dimension();
        assert_eq!(
            input.dimension(),
            expected_dimension.get(),
            "PBS input dimension mismatch"
        );
        assert_eq!(
            output.dimension(),
            expected_dimension.get(),
            "PBS output dimension mismatch"
        );

        self.resources
            .blind_rotate(input, lookup_table.polynomial(), 1);
        self.return_accumulator_to(core::iter::once(output));
    }

    /// Applies all interleaved tables into reusable ciphertext allocations.
    ///
    /// Shares one blind rotation and one ring key switch.
    ///
    /// Inherits [`ProgrammableBootstrapInterleaved::apply_interleaved_lookup_table_to`]'s input encoding,
    /// key, noise and output-scale requirements.
    ///
    /// # Panics
    ///
    /// Panics before output writes on incompatible LUT encoding/moduli/length
    /// or ciphertext dimensions. A wrong output count is also rejected.
    pub fn apply_interleaved_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &InterleavedLookupTable<T>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        let parameters = self.resources.context.parameters();
        assert!(
            lookup_table.is_compatible_with_ciphertext_domain(
                parameters.blind_rotation_params().poly_length(),
                parameters.small_modulus_value(),
                parameters.ring_modulus().explicit_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let expected_dimension = parameters.external_lwe_dimension();
        assert_eq!(
            input.dimension(),
            expected_dimension.get(),
            "PBS input dimension mismatch"
        );
        assert_eq!(
            outputs.len(),
            lookup_table.output_count(),
            "PBSManyLUT output slice length mismatch"
        );
        assert!(
            outputs
                .iter()
                .all(|output| output.dimension() == expected_dimension.get()),
            "PBSManyLUT output ciphertext dimension mismatch"
        );

        self.resources.blind_rotate(
            input,
            lookup_table.polynomial(),
            lookup_table.padded_output_count(),
        );
        self.return_accumulator_to(outputs.iter_mut().map(Lwe::as_mut_view));
    }

    /// Return a validated phase prefix. BR→KS switches the ring once before compact
    /// extraction and Q→q rounding; KS→BR directly extracts at Q under the
    /// accumulator LWE secret. Equal moduli skip the conversion pass.
    /// Iterating views lets the single-output path share extraction without an
    /// owned ciphertext wrapper or an allocated batch of view descriptors.
    #[inline]
    pub(crate) fn return_accumulator_to<'out>(
        &mut self,
        outputs: impl Iterator<Item = Lwe<&'out mut [T]>>,
    ) {
        let resources = &mut self.resources;
        let glwe = resources.context.parameters().blind_rotation_params();
        match &mut self.return_key_switching {
            Some(ks) => ks.switch_to_small(
                resources.accumulator.as_view(),
                outputs.enumerate(),
                resources.context,
                &mut resources.fft,
            ),
            None => {
                for (index, mut output) in outputs.enumerate() {
                    resources.accumulator.extract_compact_lwe_at_to(
                        index,
                        &mut output,
                        glwe.poly_length().get(),
                        glwe.cipher_modulus(),
                    );
                }
            }
        }
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    LM: RingContext<T>,
    Table: FftTable,
{
    /// Checks the server-key layout and bases before allocating reusable PBS buffers.
    ///
    /// # Correctness
    /// The server key must use the same paired secrets and FFT table instance.
    /// Compatibility checks cover layouts and parameters.
    pub fn evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<Evaluator<'a, T, Table>, TfheEvaluationError> {
        let context = self.evaluation_context();
        let key = server_key.glwe_key_switching_key();
        let resources = BootstrapResources::try_from_bound_keys(
            context,
            server_key.blind_rotation_key(),
            Some((context.parameters().glwe_key_switching(), key)),
        )?;
        Ok(Evaluator::from_resources(resources, key))
    }
}
