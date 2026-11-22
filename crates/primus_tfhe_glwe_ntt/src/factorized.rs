//! Prepared factorized MVB programs and their reusable evaluator.

use primus_glwe::NttGlweCiphertext;
use primus_integer::FheUint;
use primus_lwe::LweCiphertext;
use primus_ntt::MonomialNttTable;
use primus_poly::{NttPolynomialIter, PolynomialIterMut, PolynomialOwned};
use primus_reduce::{Modulus, RingContext};
use primus_tfhe::FactorizedLookupTable;

use crate::{Evaluator, LookupTableError, Lwe, ServerKey, TfheContext, TfheEvaluationError};

/// A factorized MVB program prepared for one borrowed NTT context.
///
/// The common polynomial stays in coefficient form; the contiguous factor buffer
/// is transformed once in place, one polynomial at a time. No coefficient-domain
/// duplicate is retained. Context identity protects the NTT root/order
/// convention, which cannot be inferred from the modulus and length alone.
pub struct NttFactorizedLookupTable<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    context: crate::context::EvaluationContext<'a, T, Table>,
    common_polynomial: PolynomialOwned<T>,
    factors: Vec<T>,
    input_domain_len: usize,
    output_plaintext_modulus: T,
}

impl<'a, T, Table> NttFactorizedLookupTable<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Consumes a coefficient program and prepares its factors with `context`.
    ///
    /// # Panics
    ///
    /// Panics if the program's polynomial length or input/coefficient modulus
    /// does not match the context, before performing any transforms.
    #[must_use]
    pub fn new<LM: RingContext<T>>(
        context: &'a TfheContext<T, Table, LM>,
        lookup_table: FactorizedLookupTable<T>,
    ) -> Self {
        let parameters = context.parameters();
        assert!(
            lookup_table.is_compatible_with_ciphertext_domain(
                parameters.blind_rotation_params().poly_length(),
                parameters.small_lwe().cipher_modulus_value(),
                parameters.ring_modulus().explicit_value(),
            ),
            "MVB lookup-table modulus or polynomial length mismatch"
        );
        let input_domain_len = lookup_table.input_domain_len();
        let output_plaintext_modulus = lookup_table.output_plaintext_modulus();
        let (common_polynomial, mut factors) = lookup_table.into_polynomials();
        for mut factor in PolynomialIterMut::new(&mut factors, common_polynomial.len()) {
            context.table().transform_slice(factor.as_mut());
        }
        Self {
            context: context.evaluation_context(),
            common_polynomial,
            factors,
            input_domain_len,
            output_plaintext_modulus,
        }
    }

    /// Returns the programmed input prefix length.
    #[must_use]
    pub fn input_domain_len(&self) -> usize {
        self.input_domain_len
    }

    /// Returns the exact output count, without interleaved padding.
    #[must_use]
    pub fn output_count(&self) -> usize {
        self.factors.len() / self.common_polynomial.len()
    }

    /// Returns the plaintext modulus of the unsigned Scaled output encoding.
    #[must_use]
    pub fn output_plaintext_modulus(&self) -> T {
        self.output_plaintext_modulus
    }
}

/// Reusable workspace for fixed-scale factorized MVB.
///
/// Shares one Classic or Block blind rotation at step one. Each output then
/// multiplies by its public difference factor. BootstrapKeyswitch performs KS
/// after each product; KeyswitchBootstrap switches the input once before BR.
/// External secrets and dimensions are the same as for [`Evaluator`].
/// Only one extra full GLWE in NTT form is allocated beyond the ordinary
/// evaluator's workspace, independently of the number of outputs.
/// Owns the ordinary evaluator, while borrowing its context and key material.
pub struct FactorizedEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    pbs: Evaluator<'a, T, Table>,
    shared_rotation: NttGlweCiphertext<Vec<T>>,
}

impl<'a, T, Table> FactorizedEvaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Takes ownership of a prepared PBS evaluator and allocates one NTT GLWE
    /// for the shared rotation. Its existing input/BR and return buffers are
    /// moved without copying key material or preparing them again. Supports
    /// Classic and Block keys and both orders.
    #[must_use]
    pub fn new(evaluator: Evaluator<'a, T, Table>) -> Self {
        let context = evaluator.resources.context;
        Self {
            pbs: evaluator,
            shared_rotation: NttGlweCiphertext::zero(
                context.parameters().blind_rotation_params().glwe_len(),
            ),
        }
    }

    /// Evaluates the program, allocating one LWE per output.
    ///
    /// Inherits [`Self::apply_lookup_table_to`]'s encoding, key, noise and context
    /// requirements, including its panic conditions.
    #[must_use]
    pub fn apply_lookup_table(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &NttFactorizedLookupTable<'_, T, Table>,
    ) -> Vec<LweCiphertext<T>> {
        let context = self.pbs.resources.context;
        let dimension = context.parameters().external_lwe_dimension();
        let mut outputs = (0..lookup_table.output_count())
            .map(|_| LweCiphertext::zero(dimension.get()))
            .collect::<Vec<_>>();
        self.apply_lookup_table_to(input, lookup_table, &mut outputs);
        outputs
    }

    /// Evaluates all factors into caller-owned outputs without allocating.
    ///
    /// # Correctness
    ///
    /// Input coefficients must be canonical under the context's modulus and use
    /// its external client secret and unsigned Rounded encoding, with a message
    /// in `0..lookup_table.input_domain_len()`. Input noise, any pre-BR KS noise,
    /// and coefficient-wise quantization error must stay within that message's
    /// LUT interval. Each difference factor amplifies the shared BR noise; BK
    /// adds a separate KS error after multiplication. These conditions are not
    /// checked. Include Q→q return rounding for BK. Decode with a Scaled codec
    /// at the external modulus and the compiled output message modulus. See
    /// [`FactorizedLookupTable`] for the factorization and noise bound.
    ///
    /// # Panics
    ///
    /// Panics before any output write unless the program was prepared by the
    /// same context instance, input and all outputs have the external LWE
    /// dimension, and the output slice has exactly the program's output count.
    pub fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &NttFactorizedLookupTable<'_, T, Table>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        let evaluator = &mut self.pbs;
        assert!(
            evaluator.resources.context.is_same(lookup_table.context),
            "MVB program was prepared by a different context"
        );
        let parameters = evaluator.resources.context.parameters();
        let dimension = parameters.external_lwe_dimension();
        assert_eq!(
            input.dimension(),
            dimension.get(),
            "MVB input dimension mismatch"
        );
        assert_eq!(
            outputs.len(),
            lookup_table.output_count(),
            "MVB output count mismatch"
        );
        assert!(
            outputs
                .iter()
                .all(|output| output.dimension() == dimension.get()),
            "MVB output ciphertext dimension mismatch"
        );

        let glwe = parameters.blind_rotation_params();
        let table = evaluator.resources.context.table();
        let resources = &mut evaluator.resources;
        resources.blind_rotate(input, &lookup_table.common_polynomial, 1);
        resources
            .accumulator
            .write_ntt_form(&mut self.shared_rotation, table);
        let factors = NttPolynomialIter::new(&lookup_table.factors, glwe.poly_length().get());
        for (factor, output) in factors.zip(outputs) {
            // Borrow the accumulator in NTT form, then restore its
            // coefficient representation before KS/extraction. The shared BR
            // result remains intact for the next output.
            let resources = &mut evaluator.resources;
            let mut product = NttGlweCiphertext::new(resources.accumulator.as_mut());
            self.shared_rotation.mul_ntt_polynomial_to(
                &factor,
                &mut product,
                glwe.cipher_modulus(),
            );
            product.into_coeff_form(table);
            evaluator.return_accumulator_to(core::iter::once(output.as_mut_view()));
        }
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    LM: RingContext<T>,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Creates an MVB evaluator owning its PBS and factor-product workspaces.
    ///
    /// Checks key compatibility once through [`Self::evaluator`]. Context and
    /// key material remain borrowed; online evaluation reuses every buffer.
    pub fn mvb_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<FactorizedEvaluator<'a, T, Table>, TfheEvaluationError> {
        self.evaluator(server_key).map(FactorizedEvaluator::new)
    }

    /// Compiles a factorized MVB program using the configured message domains.
    ///
    /// Uses Rounded input and Scaled output, including the returned external-domain
    /// decoder from [`Self::mvb_decryptor`]. `input_domain_len` is a nonempty
    /// prefix of the input front half; `output_count` is positive and unpadded.
    /// Callback order, factorization and noise requirements follow
    /// [`FactorizedLookupTable::try_new`].
    pub fn compile_mvb_fn<F>(
        &self,
        input_domain_len: usize,
        output_count: usize,
        function: F,
    ) -> Result<NttFactorizedLookupTable<'_, T, Table>, LookupTableError>
    where
        F: Fn(usize, usize) -> T,
    {
        self.compile_mvb_fn_with_messages(
            self.parameters().messages(),
            input_domain_len,
            output_count,
            function,
        )
    }

    /// Compiles MVB with independent input/output plaintext moduli.
    ///
    /// Does not change defaults or existing clients. Pair `messages.input_modulus`
    /// with [`Self::encryptor_with_message_modulus`] (or its public-key counterpart).
    /// Decode Scaled outputs with [`Self::ring_return_decryptor`] and
    /// `messages.output_modulus`; [`Self::mvb_decryptor`] uses the default modulus.
    /// Checks the Scaled LUT output at Q before compiling; the external decoder
    /// separately checks its own modulus;
    /// inherits [`FactorizedLookupTable::try_new`]'s program contracts.
    /// Factors are prepared in NTT form; evaluation requires this context instance.
    pub fn compile_mvb_fn_with_messages<F>(
        &self,
        messages: crate::PbsMessageConfig<T>,
        input_domain_len: usize,
        output_count: usize,
        function: F,
    ) -> Result<NttFactorizedLookupTable<'_, T, Table>, LookupTableError>
    where
        F: Fn(usize, usize) -> T,
    {
        let lookup_table =
            self.parameters()
                .compile_mvb_fn(messages, input_domain_len, output_count, function)?;
        Ok(NttFactorizedLookupTable::new(self, lookup_table))
    }
}
