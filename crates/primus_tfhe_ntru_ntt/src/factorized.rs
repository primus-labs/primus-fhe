//! Prepared factorized MVB programs and their reusable evaluator.

use primus_integer::FheUint;
use primus_lattice::ntru::NttNtru;
use primus_ntt::MonomialNttTable;
use primus_poly::{NttPolynomial, NttPolynomialIter, PolynomialIterMut, PolynomialOwned};
use primus_tfhe::{FactorizedLookupTable, LweCiphertext};

use crate::{Evaluator, LookupTableError, Lwe, ServerKey, TfheContext, TfheEvaluationError};

/// A factorized MVB program prepared for one borrowed NTT context.
///
/// The common polynomial stays in coefficient form; the contiguous factor buffer
/// is transformed once in place, one polynomial at a time. No coefficient-domain
/// duplicate is retained. Context identity protects the NTT root/order
/// convention, which cannot be inferred from the modulus and length alone.
/// The input reducer is used during preparation only; the program retains
/// its domain binding and transformed factors.
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
    /// Panics if the program's polynomial length or input/coefficient encoding
    /// does not match the context, before performing any transforms.
    #[must_use]
    pub fn new<LM: primus_reduce::RingContext<T>>(
        context: &'a TfheContext<T, Table, LM>,
        lookup_table: FactorizedLookupTable<T>,
    ) -> Self {
        let parameters = context.parameters();
        assert!(
            lookup_table.is_compatible_with_ciphertext_domain(
                parameters.accumulator_ntru().poly_length(),
                parameters.external_lwe().cipher_modulus_value(),
                parameters.accumulator_ntru().cipher_modulus_value(),
            ),
            "MVB lookup-table encoding or polynomial length mismatch"
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
/// Lifts and blind-rotates V using the selected PBS key at
/// rotation step one, then multiplies each public factor. Each product is
/// independently converted Q→q and extracted, then small LWE tiles share key
/// switching to the external secret.
/// Only one extra NTT polynomial is allocated beyond the ordinary evaluator's
/// workspace, regardless of output count. Owns the ordinary evaluator, while
/// borrowing its context and key material. Outputs use the same external
/// secret and dimension as [`Evaluator`].
pub struct FactorizedEvaluator<'a, T, Table, LM = primus_modulus::BarrettModulus<T>>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    pbs: Evaluator<'a, T, Table, LM>,
    shared_rotation: NttNtru<Vec<T>>,
}

impl<'a, T, Table, LM> FactorizedEvaluator<'a, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Takes ownership of a prepared PBS evaluator and allocates one extra NTT
    /// polynomial for MVB. Its existing BR and scalar/batch return buffers are
    /// moved without copying key material or preparing them again.
    /// Classic and Block keys use the same factor/return path.
    #[must_use]
    pub fn new(evaluator: Evaluator<'a, T, Table, LM>) -> Self {
        let context = evaluator.resources.context;
        Self {
            pbs: evaluator,
            shared_rotation: NttNtru::zero(context.poly_length().get()),
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
        let dimension = context.external_lwe_dimension();
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
    /// in `0..lookup_table.input_domain_len()`. Input noise and coefficient-wise
    /// quantization error must stay within that message's LUT interval. Each
    /// difference factor amplifies the shared public-lift and BR noise. Modulus
    /// conversion and LWE key-switch errors
    /// follow each product. These conditions are not checked. The output scale
    /// is q/Q times the compilation scale. Decode using a Scaled
    /// codec at q with the same plaintext modulus, budgeting the difference
    /// between that rescaled scale and round(q/t_out). See
    /// [`FactorizedLookupTable`] for the factorization and noise bound.
    ///
    /// # Panics
    ///
    /// Panics before any output write unless the program was prepared by the
    /// same context instance, input and all outputs have the external LWE
    /// dimension, and the output slice has exactly the program's output count.
    /// A new valid request supersedes pending return samples from a previous
    /// interrupted MVB request.
    pub fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &NttFactorizedLookupTable<'_, T, Table>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        self.check_io(input.as_view(), lookup_table, outputs);
        self.prepare_shared_rotation(input, &lookup_table.common_polynomial);

        let n = self.pbs.resources.context.poly_length().get();
        let mut factors = NttPolynomialIter::new(&lookup_table.factors, n);
        for outputs in outputs.chunks_mut(self.pbs.batch_return.batch_capacity()) {
            self.pbs.batch_return.begin_batch();
            for factor in factors.by_ref().take(outputs.len()) {
                self.prepare_factor_product(factor);
                let evaluator = &mut self.pbs;
                evaluator.lwe_return.append_at(
                    evaluator.resources.blind_rotation.current.as_view(),
                    0,
                    &mut evaluator.batch_return,
                );
            }
            self.pbs
                .lwe_return
                .return_batch_to(outputs, &mut self.pbs.batch_return);
        }
    }

    /// Validate context identity and every ciphertext before BR mutates scratch.
    /// The prepared program fixes factor count and transform layout for this context.
    fn check_io(
        &self,
        input: Lwe<&[T]>,
        lookup_table: &NttFactorizedLookupTable<'_, T, Table>,
        outputs: &[LweCiphertext<T>],
    ) {
        assert!(
            self.pbs.resources.context.is_same(lookup_table.context),
            "MVB program was prepared by a different context"
        );
        let parameters = self.pbs.resources.context;
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
    }

    /// Preserve the common blind rotation in transform form for all factors.
    /// Individual products can then overwrite the coefficient accumulator.
    fn prepare_shared_rotation(&mut self, input: Lwe<&[T]>, common: &PolynomialOwned<T>) {
        let resources = &mut self.pbs.resources;
        resources.blind_rotate(input, common, 1);
        resources
            .blind_rotation
            .current
            .write_ntt_form(&mut self.shared_rotation, resources.context.table());
    }

    /// Multiply one factor into the reusable coefficient accumulator.
    /// The caller returns its phase before the next factor overwrites the product.
    fn prepare_factor_product(&mut self, factor: NttPolynomial<&[T]>) {
        let resources = &mut self.pbs.resources;
        let parameters = resources.context;
        let mut product = NttNtru::new(resources.blind_rotation.current.as_mut());
        self.shared_rotation.mul_ntt_polynomial_to(
            &factor,
            &mut product,
            parameters.accumulator_ntru().cipher_modulus(),
        );
        product.into_coeff_form(resources.context.table());
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Creates an MVB evaluator owning its PBS and factor-product workspaces.
    ///
    /// Checks key compatibility once through [`Self::evaluator`]. Context and
    /// key material remain borrowed; online evaluation reuses every buffer.
    /// Inherits [`Evaluator::try_new`]'s material requirements.
    pub fn mvb_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<FactorizedEvaluator<'a, T, Table, LM>, TfheEvaluationError> {
        self.evaluator(server_key).map(FactorizedEvaluator::new)
    }

    /// Compiles a factorized MVB program using the configured message domains.
    ///
    /// Uses Rounded input and Scaled output, including the returned external-q
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
    /// Checks the Scaled LUT output at Q and returned output at q before compiling;
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
        let codecs = self.parameters().factorized_pbs_codecs(messages)?;
        let lookup_table = self.parameters().compile_factorized_lookup_table_fn(
            &codecs,
            input_domain_len,
            output_count,
            function,
        )?;
        Ok(NttFactorizedLookupTable::new(self, lookup_table))
    }
}
