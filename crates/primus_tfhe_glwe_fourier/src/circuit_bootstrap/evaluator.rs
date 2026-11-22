use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_glwe::{GlevCiphertext, GlweCiphertext};
use primus_lattice::ggsw::FourierGgsw;
use primus_tfhe::CircuitBootstrapLookupTable;

use super::key::CircuitBootstrapBinding;
use super::trace::CbsTraceWorkspace;
use crate::{
    Lwe, TfheEvaluationError,
    bootstrap::BootstrapResources,
    circuit_bootstrap::{CbsGadgetParameters, CircuitBootstrapKey},
};

/// Classic or Block CBS producing Fourier GGSW controls.
///
/// Owns the programmed LUT and projection buffers. Common input/BR/FFT/EP
/// resources are borrowed per call; both BR variants share trace and scheme switching.
/// After construction, [`Self::circuit_bootstrap_to`] performs no heap allocation.
pub struct CircuitBootstrapEvaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    context: crate::context::EvaluationContext<'a, T, Table>,
    circuit: CircuitBootstrapBinding<'a, T>,
    lookup_table: CircuitBootstrapLookupTable<T>,
    trace: CbsTraceWorkspace<T>,
    projected: GlevCiphertext<Vec<T>>,
}

impl<'a, T, Table> CircuitBootstrapEvaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Binds an independently compiled program and CBS material before allocating scratch.
    /// Compile identity or a custom function through the Context or
    /// [`CbsGadgetParameters`] first. The program is moved without cloning.
    ///
    /// Pass `circuit_key.parameters()` for its original output basis, or select
    /// a compatible basis with the same key layout. Checks the key/parameters
    /// and program's N, q/Q and exact output basis at this binding boundary.
    /// Common resources are borrowed only for construction and each online call;
    /// both Classic and Block BR support either PBS order.
    ///
    /// # Correctness
    /// CBS and resource keys must use the same paired secrets and this context's
    /// FFT table instance. Checks do not establish those identities or a noise
    /// margin; see [`primus_glwe::FourierGlweSchemeSwitchKey::apply_to`].
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
        context: crate::context::EvaluationContext<'a, T, Table>,
        circuit: CircuitBootstrapBinding<'a, T>,
        lookup_table: CircuitBootstrapLookupTable<T>,
    ) -> Self {
        let parameters = circuit.parameters;
        let trace = circuit
            .key
            .trace_key()
            .new_workspace(parameters.output_size().glwe_size());
        Self {
            context,
            circuit,
            lookup_table,
            trace,
            projected: GlevCiphertext::zero(parameters.output_size().glev_len()),
        }
    }

    /// Allocates a zeroed Fourier GGSW with this evaluator's output layout.
    /// Allocate once and reuse it with [`Self::circuit_bootstrap_to`].
    #[must_use]
    pub fn allocate_output(&self) -> FourierGgsw<Vec<Complex64>> {
        FourierGgsw::zero(self.circuit.parameters.output_size().fourier_ggsw_len())
    }

    /// Allocates a Fourier GGSW output. Inherits [`Self::circuit_bootstrap_to`]'s
    /// encoding, secret, FFT representation, noise and borrowing contracts.
    #[must_use]
    pub fn circuit_bootstrap(
        &mut self,
        input: Lwe<&[T]>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) -> FourierGgsw<Vec<Complex64>> {
        let mut output = self.allocate_output();
        self.circuit_bootstrap_to(input, output.as_mut_view(), resources);
        output
    }

    /// Writes a Fourier GGSW encrypting F(m) under the accumulator
    /// GLWE secret, with the configured output gadget scalars.
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::try_new`]'s paired-secret and FFT table requirements.
    /// Input must use the external client secret paired with the bound BR/KS material and
    /// the program's padded or MSB Boolean encoding. Noise must fit that program's
    /// rotation intervals. Trace and scheme-switch errors, including native
    /// halving and FFT rounding, must fit the independent CBS error budget;
    /// see [`CbsGadgetParameters`]. For Block BR, budget the aggregation noise
    /// from all selectors and any dummies, plus the aggregate FFT error. CMux
    /// requires `F(m)` in `{0, 1}`
    /// throughout the programmed domain. The default identity uses `F(m)=m`.
    /// The output uses gadget scales rather than ordinary LWE encoding.
    ///
    /// # Panics
    ///
    /// Panics before output writes if the input dimension or output Fourier
    /// GGSW length is wrong, or resources belong to a different context.
    /// LUT parameters are fixed during construction.
    pub fn circuit_bootstrap_to(
        &mut self,
        input: Lwe<&[T]>,
        mut output: FourierGgsw<&mut [Complex64]>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) {
        resources.check_context(self.context);
        let parameters = self.circuit.parameters;
        let circuit_key = self.circuit.key;
        assert_eq!(
            input.dimension(),
            resources
                .context
                .parameters()
                .external_lwe_dimension()
                .get(),
            "circuit-bootstrap input dimension mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            parameters.output_size().fourier_ggsw_len(),
            "circuit-bootstrap output Fourier GGSW layout mismatch"
        );

        let (accumulator, fft) = resources.blind_rotate(
            input,
            self.lookup_table.polynomial(),
            self.lookup_table.padded_output_count(),
        );
        // ManyLUT messages can have nonzero tails, so prefix expansion cannot
        // replace full coefficient projection here.
        circuit_key.trace_key().project_to(
            accumulator.as_view(),
            parameters.output_basis().level_count().get(),
            self.projected.as_mut(),
            fft,
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
            .zip(self.projected.iter_glwe_mut(size.glwe_len()))
        {
            let (_, body) = lane.a_b_mut_slices(size.poly_length().get());
            body[0] = body[0].wrapping_add(*offset);
        }
        // CMUX can bind the same buffers to a different output decomposition.
        resources.with_external_product(parameters.scheme_switch().size(), |scratch, fft| {
            circuit_key
                .scheme_switch_key()
                .apply_to(&self.projected, &mut output, fft, scratch);
        });
    }
}

// Operations that consume a CBS control using the shared product scratch.
impl<'a, T, Table> CircuitBootstrapEvaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Selects `lhs` for an encrypted zero and `rhs` for an encrypted one.
    /// Overwrites the coefficient-domain output without allocating or resetting scratch.
    ///
    /// # Correctness
    /// `control` must encrypt a bit with this evaluator's output basis, accumulator
    /// secret and transform representation. Both candidates must use that secret,
    /// modulus and the same encoding; their noise must permit the external product.
    /// Fourier controls must use the bound FFT table instance.
    /// See [`FourierGgsw::cmux_to`] for the underlying numerical contract.
    ///
    /// # Panics
    /// Panics before output writes on a different resource context or a wrong ciphertext length.
    pub fn cmux_to(
        &mut self,
        control: FourierGgsw<&[Complex64]>,
        lhs: GlweCiphertext<&[T]>,
        rhs: GlweCiphertext<&[T]>,
        mut output: GlweCiphertext<&mut [T]>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) {
        resources.check_context(self.context);
        let parameters = self.circuit.parameters;
        let ring_len = parameters.output_size().glwe_size().glwe_len();
        assert_eq!(
            (
                control.as_ref().len(),
                lhs.as_ref().len(),
                rhs.as_ref().len(),
                output.as_ref().len()
            ),
            (
                parameters.output_size().fourier_ggsw_len(),
                ring_len,
                ring_len,
                ring_len
            ),
            "CMUX ciphertext layout mismatch"
        );
        resources.with_external_product(parameters.output_size(), |scratch, fft| {
            control.cmux_to(
                &lhs,
                &rhs,
                &mut output,
                parameters.output_basis(),
                fft,
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
    /// See [`FourierGgsw::external_product_to`].
    ///
    /// # Panics
    /// Panics before output writes on a different resource context or a wrong ciphertext length.
    pub fn external_product_to(
        &mut self,
        control: FourierGgsw<&[Complex64]>,
        input: GlweCiphertext<&[T]>,
        mut output: GlweCiphertext<&mut [T]>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) {
        resources.check_context(self.context);
        let parameters = self.circuit.parameters;
        let ring_len = parameters.output_size().glwe_size().glwe_len();
        assert_eq!(
            (
                control.as_ref().len(),
                input.as_ref().len(),
                output.as_ref().len()
            ),
            (
                parameters.output_size().fourier_ggsw_len(),
                ring_len,
                ring_len
            ),
            "external-product ciphertext layout mismatch"
        );
        resources.with_external_product(parameters.output_size(), |scratch, fft| {
            control.external_product_to(
                &input,
                &mut output,
                parameters.output_basis(),
                fft,
                scratch,
            );
        });
    }
}
