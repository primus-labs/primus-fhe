//! Patched NTT circuit bootstrapping using PBSManyLUT, reverse-trace projection, and scheme
//! switching.

use primus_data::{Data, DataMut};
use primus_glwe::{GlevCiphertext, GlweCiphertext, NttGlweTraceWorkspace};
use primus_integer::FheUint;
use primus_lattice::ggsw::NttGgsw;
use primus_ntt::MonomialNttTable;
use primus_reduce::ReduceAdd;
use primus_tfhe::CircuitBootstrapLookupTable;

use super::key::CircuitBootstrapBinding;
use crate::{
    Lwe, TfheEvaluationError,
    bootstrap::BootstrapResources,
    circuit_bootstrap::{CbsGadgetParameters, CircuitBootstrapKey},
    context::EvaluationContext,
};

/// Classic binary/ternary or sparse binary CBS producing NTT GGSW controls.
///
/// Owns the programmed LUT and projection buffers. Common input/BR/EP resources
/// are borrowed per call; both BR variants share trace and scheme switching.
///
/// After construction, [`Self::circuit_bootstrap_to`] reuses all scratch
/// buffers and performs no heap allocation.
pub struct CircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    context: EvaluationContext<'a, T, Table>,
    circuit: CircuitBootstrapBinding<'a, T>,
    lookup_table: CircuitBootstrapLookupTable<T>,
    trace: NttGlweTraceWorkspace<T>,
    traced: GlevCiphertext<Vec<T>>,
}

impl<'a, T, Table> CircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Binds an independently compiled program and CBS material before allocating scratch.
    /// Compile identity or a custom function through the Context or
    /// [`CbsGadgetParameters`] first. The program is moved without cloning.
    ///
    /// Pass `circuit_key.parameters()` for its original output basis, or select
    /// a compatible basis with the same key layout. Checks the key/parameters
    /// and program's N, q/Q and exact output basis at this binding boundary.
    /// Common resources are borrowed only for construction and each online call;
    /// both classic/sparse BR and both PBS orders are supported.
    ///
    /// # Correctness
    /// CBS and resource keys must use the same paired secrets and this context's
    /// NTT representation. Checks do not establish those identities or a noise
    /// margin; see [`primus_glwe::NttGlweSchemeSwitchKey::apply_to`].
    /// Inputs must use the encoding selected at program compilation. CMux requires
    /// the programmed function to return a bit throughout its domain.
    pub fn try_new(
        resources: &BootstrapResources<'a, T, Table>,
        parameters: &'a CbsGadgetParameters<T>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        lookup_table: CircuitBootstrapLookupTable<T>,
    ) -> Result<Self, TfheEvaluationError> {
        let context = resources.context;
        let circuit = CircuitBootstrapBinding::try_new(
            context.parameters(),
            parameters,
            circuit_key,
            &lookup_table,
        )?;
        Ok(Self::from_binding(context, circuit, lookup_table))
    }

    /// Allocates projection storage after the entry point has established the key,
    /// parameters and program pairing. Both owned and borrowed workflows use
    /// this allocation path without repeating the binding checks.
    pub(super) fn from_binding(
        context: EvaluationContext<'a, T, Table>,
        circuit: CircuitBootstrapBinding<'a, T>,
        lookup_table: CircuitBootstrapLookupTable<T>,
    ) -> Self {
        let parameters = circuit.parameters;
        Self {
            context,
            circuit,
            lookup_table,
            trace: NttGlweTraceWorkspace::new(parameters.output_size().glwe_size()),
            traced: GlevCiphertext::zero(parameters.output_size().glev_len()),
        }
    }

    /// Allocates a zeroed NTT GGSW with this evaluator's output layout.
    /// Allocate once and reuse it with [`Self::circuit_bootstrap_to`].
    #[must_use]
    pub fn allocate_output(&self) -> NttGgsw<Vec<T>> {
        NttGgsw::zero(self.circuit.parameters.output_size().ggsw_len())
    }

    /// Circuit-bootstraps into a newly allocated NTT GGSW ciphertext.
    ///
    /// The output uses the gadget scalars described by [`Self::circuit_bootstrap_to`].
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::circuit_bootstrap_to`]'s input encoding, plaintext domain,
    /// canonical-residue, noise and key/NTT representation requirements.
    ///
    /// # Panics
    ///
    /// Panics if the input dimension differs from the configured external LWE
    /// dimension, or resources belong to a different context. The output uses
    /// the configured GGSW length.
    #[must_use]
    pub fn circuit_bootstrap(
        &mut self,
        input: Lwe<&[T]>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) -> NttGgsw<Vec<T>> {
        let mut output = self.allocate_output();
        self.circuit_bootstrap_to(input, &mut output, resources);
        output
    }

    /// Converts an external LWE ciphertext into an NTT GGSW under the main
    /// GLWE key, encrypting the programmed F(m). Output levels preserve the gadget scalars compiled by this
    /// evaluator; they do not use the ordinary LWE plaintext scale.
    ///
    /// # Correctness
    ///
    /// The key/NTT representation requirements of [`Self::try_new`] must hold.
    /// Input must use the external secret paired with the bound BR/KS material,
    /// this context's external LWE modulus and the bound program's padded or MSB
    /// Boolean encoding, with canonical residues. Noise must fit that program's
    /// rotation intervals; trace and scheme-switching errors must also fit the independent CBS
    /// budget described by [`CbsGadgetParameters`]. For sparse keys, include
    /// aggregation noise from every bucket, including zero selections and dummies.
    /// CMux requires `F(m)` in `{0, 1}` throughout the programmed domain.
    /// The output remains under the accumulator GLWE
    /// secret and uses gadget scales, not ordinary LWE or Boolean encoding.
    /// The default identity program uses `F(m)=m`.
    ///
    /// # Panics
    ///
    /// Panics before output writes if the input dimension differs from the
    /// configured external LWE dimension or the output length differs from the
    /// configured GGSW length, or resources belong to a different context.
    /// LUT parameters are fixed during construction.
    pub fn circuit_bootstrap_to<S>(
        &mut self,
        input: Lwe<&[T]>,
        output: &mut NttGgsw<S>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) where
        S: DataMut<Elem = T>,
    {
        resources.check_context(self.context);
        let parameters = self.circuit.parameters;
        let circuit_key = self.circuit.key;
        let context = resources.context;
        let tfhe = context.parameters();
        assert_eq!(
            input.dimension(),
            tfhe.external_lwe_dimension().get(),
            "circuit-bootstrap input dimension mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            parameters.output_size().ggsw_len(),
            "circuit-bootstrap output GGSW layout mismatch"
        );

        let accumulator = resources.blind_rotate(
            input,
            self.lookup_table.polynomial(),
            self.lookup_table.padded_output_count(),
        );

        circuit_key.trace_key().project_prefix_coefficients_to(
            accumulator,
            parameters.output_basis().level_count().get(),
            self.traced.as_mut(),
            context
                .parameters()
                .blind_rotation_params()
                .cipher_modulus(),
            context.table(),
            &mut self.trace,
        );
        // The centered MSB LUT gives -h/h. Correct only after full trace:
        // native normalization rounds, so adding the offset before it is invalid.
        // Padded programs have no offsets and perform no work here.
        let size = parameters.output_size().glwe_size();
        for (offset, mut lane) in self
            .lookup_table
            .post_trace_offsets()
            .iter()
            .zip(self.traced.iter_glwe_mut(size.glwe_len()))
        {
            let (_, body) = lane.a_b_mut_slices(size.poly_length().get());
            body[0] = tfhe.ring_modulus().reduce_add(body[0], *offset);
        }
        // CMUX can bind the same buffers to a different output decomposition.
        resources.with_external_product(parameters.scheme_switch().size(), |scratch| {
            circuit_key.scheme_switch_key().apply_to(
                &self.traced,
                output,
                context
                    .parameters()
                    .blind_rotation_params()
                    .cipher_modulus(),
                context.table(),
                scratch,
            );
        });
    }
}

// Operations that consume a CBS control using the shared product scratch.
impl<'a, T, Table> CircuitBootstrapEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Selects `lhs` for an encrypted zero and `rhs` for an encrypted one.
    /// Overwrites the coefficient-domain output without allocating or resetting scratch.
    ///
    /// # Correctness
    /// `control` must encrypt a bit with this evaluator's output basis, accumulator
    /// secret and transform representation. Both candidates must use that secret,
    /// modulus and the same encoding; their noise must permit the external product.
    /// All coefficient-domain inputs must be canonical residues.
    /// See [`NttGgsw::cmux_to`] for the underlying numerical contract.
    ///
    /// # Panics
    /// Panics before output writes on a different resource context or a wrong ciphertext length.
    pub fn cmux_to<A, B, C, D>(
        &mut self,
        control: &NttGgsw<A>,
        lhs: &GlweCiphertext<B>,
        rhs: &GlweCiphertext<C>,
        output: &mut GlweCiphertext<D>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        resources.check_context(self.context);
        let parameters = self.circuit.parameters;
        let context = resources.context;
        let ring_len = parameters.output_size().glwe_size().glwe_len();
        assert_eq!(
            (
                control.as_ref().len(),
                lhs.as_ref().len(),
                rhs.as_ref().len(),
                output.as_ref().len()
            ),
            (
                parameters.output_size().ggsw_len(),
                ring_len,
                ring_len,
                ring_len
            ),
            "CMUX ciphertext layout mismatch"
        );
        resources.with_external_product(parameters.output_size(), |scratch| {
            control.cmux_to(
                lhs,
                rhs,
                output,
                parameters.output_basis(),
                context
                    .parameters()
                    .blind_rotation_params()
                    .cipher_modulus(),
                context.table(),
                scratch,
            );
        });
    }

    /// Multiplies a coefficient-domain accumulator ciphertext by a gadget control.
    /// Overwrites output without allocating. The control need not encrypt a bit.
    ///
    /// # Correctness
    /// Inherits [`Self::cmux_to`]'s basis, secret, encoding, transform and residue
    /// requirements, with the noise budget appropriate to this multiplication.
    /// See [`NttGgsw::external_product_to`].
    ///
    /// # Panics
    /// Panics before output writes on a different resource context or a wrong ciphertext length.
    pub fn external_product_to<A, B, C>(
        &mut self,
        control: &NttGgsw<A>,
        input: &GlweCiphertext<B>,
        output: &mut GlweCiphertext<C>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) where
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        resources.check_context(self.context);
        let parameters = self.circuit.parameters;
        let context = resources.context;
        let ring_len = parameters.output_size().glwe_size().glwe_len();
        assert_eq!(
            (
                control.as_ref().len(),
                input.as_ref().len(),
                output.as_ref().len()
            ),
            (parameters.output_size().ggsw_len(), ring_len, ring_len),
            "external-product ciphertext layout mismatch"
        );
        resources.with_external_product(parameters.output_size(), |scratch| {
            control.external_product_to(
                input,
                output,
                parameters.output_basis(),
                context
                    .parameters()
                    .blind_rotation_params()
                    .cipher_modulus(),
                context.table(),
                scratch,
            );
        });
    }
}
