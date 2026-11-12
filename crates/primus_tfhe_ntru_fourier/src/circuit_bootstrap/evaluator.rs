//! One blind rotation followed by reverse-trace projection and scheme switching.

use primus_data::{Data, DataMut};
use primus_encoding::RoundedCodec;
use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_ntru::{FourierNgswCiphertext, NtruCiphertext};
use primus_tfhe::{CircuitBootstrapLookupTable, LookupTableError};

use crate::{
    Lwe, TfheContext, TfheEvaluationError, bootstrap::BootstrapResources,
    circuit_bootstrap::CircuitBootstrapKey, context::EvaluationContext,
};

/// Prepared NTRU circuit-bootstrapping LUT and projection buffers.
/// The input reducer is needed only at construction; execution retains its
/// domain binding and uses ring arithmetic.
/// Common BR/FFT/EP resources are borrowed per operation; no return buffers are owned.
/// Output is NGSW under f_acc, unlike ordinary PBS's LWE output under independent s at q.
pub struct CircuitBootstrapEvaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    context: EvaluationContext<'a, T, Table>,
    circuit_key: &'a CircuitBootstrapKey<T>,
    lookup_table: CircuitBootstrapLookupTable<T>,
    projection: super::key::ProjectionWorkspace<T>,
}

impl<'a, T, Table> CircuitBootstrapEvaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Binds the circuit key, compiles the gadget-scaled identity LUT, and allocates
    /// projection scratch. Common BR resources are supplied only for online calls
    /// and must come from the same context.
    ///
    /// # Correctness
    /// The circuit key must share the context's intended accumulator secret and
    /// FFT table instance; compatibility checks do not establish these identities.
    /// Independent BR resources must preserve both secrets.
    pub fn try_new<LM: primus_reduce::RingContext<T>>(
        context: &'a TfheContext<T, Table, LM>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        input_codec: &RoundedCodec<T, LM>,
    ) -> Result<Self, TfheEvaluationError> {
        let tfhe = context.parameters();
        circuit_key.check_parameters(context)?;
        if input_codec.ciphertext_modulus().explicit_value()
            != tfhe.external_lwe().cipher_modulus_value()
        {
            return Err(LookupTableError::InputModulusMismatch.into());
        }
        let lookup_table = circuit_key.parameters().compile_lookup_table(input_codec)?;
        Ok(Self::from_lookup_table(
            context.evaluation_context(),
            circuit_key,
            lookup_table,
        ))
    }

    /// Binds a precompiled integer CBS program without cloning or recompilation.
    /// Checks its N, external q, accumulator Q and exact output gadget basis
    /// against the circuit key before allocating projection storage.
    ///
    /// # Correctness
    /// Inherits [`Self::try_new`]'s secret and representation requirements. Noise
    /// must satisfy [`Self::circuit_bootstrap_to`] and the consuming operation.
    /// Inputs must use the encoding selected at program compilation. CMux requires
    /// the function to return a bit throughout the programmed input domain.
    pub fn try_with_lookup_table<LM: primus_reduce::RingContext<T>>(
        context: &'a TfheContext<T, Table, LM>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        lookup_table: CircuitBootstrapLookupTable<T>,
    ) -> Result<Self, TfheEvaluationError> {
        let tfhe = context.parameters();
        circuit_key.check_parameters(context)?;
        if lookup_table.input_encoding() != primus_tfhe::CbsInputEncoding::Padded
            || !lookup_table.is_compatible(
                tfhe.poly_length(),
                tfhe.external_lwe().cipher_modulus_value(),
                circuit_key.parameters().output_basis(),
            )
        {
            return Err(TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable);
        }
        Ok(Self::from_lookup_table(
            context.evaluation_context(),
            circuit_key,
            lookup_table,
        ))
    }

    /// Allocates projection storage after compilation or external program binding
    /// establishes the program/key/context pairing. No checks are repeated here.
    pub(super) fn from_lookup_table(
        context: EvaluationContext<'a, T, Table>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        lookup_table: CircuitBootstrapLookupTable<T>,
    ) -> Self {
        Self {
            context,
            circuit_key,
            lookup_table,
            projection: super::key::ProjectionWorkspace::new(circuit_key),
        }
    }

    /// Allocates a zeroed Fourier NGSW with this evaluator's output layout.
    /// Allocate once and reuse it with [`Self::circuit_bootstrap_to`].
    #[must_use]
    pub fn allocate_output(&self) -> FourierNgswCiphertext<Vec<Complex64>> {
        FourierNgswCiphertext::zero(self.circuit_key.parameters().output_fourier_nlev_len())
    }

    /// Allocates the output NGSW. Inherits [`Self::circuit_bootstrap_to`]'s contracts.
    #[must_use]
    pub fn circuit_bootstrap(
        &mut self,
        input: Lwe<&[T]>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) -> FourierNgswCiphertext<Vec<Complex64>> {
        let mut output = self.allocate_output();
        self.circuit_bootstrap_to(input, &mut output, resources);
        output
    }

    /// Writes `NGSW_f_acc[F(m)]` with the configured output gadget scalars.
    /// Reuses one BR, trace workspace and coefficient NLev allocation.
    ///
    /// # Correctness
    /// Input uses this context's external client secret, modulus and unsigned
    /// rounded LWE encoding, with m in `0..ceil(t/2)`. Canonical residues and a
    /// noise margin for the coarser ManyLUT windows are required. Trace and
    /// scheme-switch errors must fit the independent CBS budget, including f/f²
    /// amplification, native halving and FFT rounding; see
    /// [`crate::circuit_bootstrap::CbsGadgetParameters`]. CMux requires `F(m)` in `{0, 1}`
    /// throughout the programmed domain.
    /// The default identity program uses `F(m)=m`. The output uses gadget scales,
    /// not ordinary plaintext or Boolean encoding.
    ///
    /// # Panics
    /// Panics before output writes if input dimension or output NGSW length is
    /// wrong, or resources use a different context binding. Fixed LUT
    /// geometry was checked during construction.
    pub fn circuit_bootstrap_to<S: DataMut<Elem = Complex64>>(
        &mut self,
        input: Lwe<&[T]>,
        output: &mut FourierNgswCiphertext<S>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) {
        resources.check_context(self.context);
        let parameters = self.circuit_key.parameters();
        let circuit_key = self.circuit_key;
        let tfhe = resources.context;
        assert_eq!(
            input.dimension(),
            tfhe.external_lwe_dimension().get(),
            "circuit-bootstrap input dimension mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            parameters.output_fourier_nlev_len(),
            "circuit-bootstrap NGSW output length mismatch"
        );
        resources.blind_rotate(
            input,
            self.lookup_table.polynomial(),
            self.lookup_table.padded_output_count(),
        ); // A general ManyLUT accumulator does not have a zero message tail.
        // Reverse-trace projection is valid here; prefix expansion is not.
        circuit_key.project_ngsw(
            resources.blind_rotation.current.as_view(),
            output.as_mut(),
            &mut self.projection,
            &mut resources.fft,
            resources.blind_rotation.rotation.external_product(),
            resources.blind_rotation.split.as_mut(),
        );
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
    /// See [`FourierNgswCiphertext::cmux_to`] for the underlying numerical contract.
    ///
    /// # Panics
    /// Panics before output writes on a different context binding or a
    /// wrong ciphertext length.
    pub fn cmux_to<A, B, C, D>(
        &self,
        control: &FourierNgswCiphertext<A>,
        lhs: &NtruCiphertext<B>,
        rhs: &NtruCiphertext<C>,
        output: &mut NtruCiphertext<D>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) where
        A: Data<Elem = Complex64>,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        resources.check_context(self.context);
        super::control::cmux_to(
            self.circuit_key.parameters(),
            control.as_view(),
            lhs.as_view(),
            rhs.as_view(),
            output.as_mut_view(),
            resources,
        );
    }

    /// Multiplies a coefficient-domain accumulator ciphertext by a gadget control.
    /// Overwrites output without allocating. The control need not encrypt a bit.
    ///
    /// # Correctness
    /// Inherits [`Self::cmux_to`]'s basis, secret, encoding, transform and residue
    /// requirements, with the noise budget appropriate to this multiplication.
    /// See [`FourierNgswCiphertext::external_product_to`].
    ///
    /// # Panics
    /// Panics before output writes on a different context binding or a
    /// wrong ciphertext length.
    pub fn external_product_to<A, B, C>(
        &self,
        control: &FourierNgswCiphertext<A>,
        input: &NtruCiphertext<B>,
        output: &mut NtruCiphertext<C>,
        resources: &mut BootstrapResources<'a, T, Table>,
    ) where
        A: Data<Elem = Complex64>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        resources.check_context(self.context);
        super::control::external_product_to(
            self.circuit_key.parameters(),
            control.as_view(),
            input.as_view(),
            output.as_mut_view(),
            resources,
        );
    }
}
