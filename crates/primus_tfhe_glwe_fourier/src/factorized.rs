//! Prepared factorized MVB programs and their reusable evaluator.

use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_lattice::glwe::FourierGlwe;
use primus_lwe::LweCiphertext;
use primus_poly::{FourierPolynomial, FourierPolynomialIter, PolynomialIter, PolynomialOwned};
use primus_reduce::{Modulus, RingContext};
use primus_tfhe::FactorizedLookupTable;

use crate::{Evaluator, LookupTableError, Lwe, ServerKey, TfheContext, TfheEvaluationError};

/// Native even-scale MVB program prepared for one borrowed Fourier context.
///
/// V stays in coefficient form. Factors are stored contiguously as Fourier
/// transforms of signed integers, without torus scaling. Their coefficient
/// storage is discarded after preparation. Context identity protects the FFT
/// layout and ordering, which polynomial length alone cannot establish.
pub struct FourierFactorizedLookupTable<'a, T: TorusFftValue, Table: FftTable> {
    context: crate::context::EvaluationContext<'a, T, Table>,
    common_polynomial: PolynomialOwned<T>,
    factors: Vec<Complex64>,
    input_domain_len: usize,
    output_plaintext_modulus: T,
}

impl<'a, T: TorusFftValue, Table: FftTable> FourierFactorizedLookupTable<'a, T, Table> {
    /// Consumes a compatible Native coefficient program and transforms its factors.
    ///
    /// Uses the signed lifts of the factor residues. Floating-point conversion,
    /// FFT and later multiplication introduce error; this constructor does not
    /// establish a noise budget, even when the integer lifts fit exactly in f64.
    ///
    /// # Panics
    ///
    /// Panics before transforming unless T is u32/u64 and the program's ring
    /// length, input modulus and coefficient modulus match this context.
    #[must_use]
    pub fn new<LM: RingContext<T>>(
        context: &'a TfheContext<T, Table, LM>,
        lookup_table: FactorizedLookupTable<T>,
    ) -> Self {
        assert!(
            matches!(T::BITS, 32 | 64),
            "Fourier MVB requires u32 or u64 coefficients"
        );
        let parameters = context.parameters();
        let n = parameters.blind_rotation_params().poly_length().get();
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
        let (common_polynomial, coefficients) = lookup_table.into_polynomials();
        let mut factors = vec![Complex64::default(); coefficients.len() / 2];
        let mut fft = context.new_fft_engine();
        for (input, output) in
            PolynomialIter::new(&coefficients, n).zip(factors.chunks_exact_mut(n / 2))
        {
            fft.forward_as_integer(input.as_ref(), output);
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
        self.factors.len() / self.context.table().fourier_length()
    }

    /// Returns the plaintext modulus of the shared unsigned Scaled output codec.
    #[must_use]
    pub fn output_plaintext_modulus(&self) -> T {
        self.output_plaintext_modulus
    }
}

/// Reusable workspace for native even-scale MVB with Classic or Block BR.
///
/// Both PBS orders retain their usual external secrets and dimensions. BK does
/// KS after each product; KB switches the input once before the shared BR.
/// In addition to the ordinary evaluator, this allocates one Fourier GLWE and
/// one Fourier polynomial: `(d+2)*N/2` complex values, independent of output count.
/// The product is inverse-transformed one component at a time into the existing
/// coefficient GLWE. Owns the ordinary evaluator, including its single FFT
/// engine and return stage, while borrowing its context and key material.
pub struct FactorizedEvaluator<'a, T: TorusFftValue, Table: FftTable> {
    pbs: Evaluator<'a, T, Table>,
    shared_rotation: FourierGlwe<Vec<Complex64>>,
    product: FourierPolynomial<Vec<Complex64>>,
}

impl<'a, T: TorusFftValue, Table: FftTable> FactorizedEvaluator<'a, T, Table> {
    /// Takes ownership of a prepared PBS evaluator and allocates the shared
    /// Fourier GLWE and one component-sized product. Its existing input/BR/FFT
    /// and return buffers are moved without copying key material or preparing
    /// them again. Supports Classic and Block keys in both orders.
    #[must_use]
    pub fn new(evaluator: Evaluator<'a, T, Table>) -> Self {
        let context = evaluator.resources.context;
        Self {
            pbs: evaluator,
            shared_rotation: FourierGlwe::zero(
                context.parameters().blind_rotation_params().glwe_len() / 2,
            ),
            product: FourierPolynomial::zero(
                context
                    .parameters()
                    .blind_rotation_params()
                    .poly_length()
                    .fourier_poly_len(),
            ),
        }
    }

    /// Evaluates the program, allocating one LWE ciphertext per output.
    /// Inherits [`Self::apply_lookup_table_to`]'s correctness and panic contracts.
    #[must_use]
    pub fn apply_lookup_table(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &FourierFactorizedLookupTable<'_, T, Table>,
    ) -> Vec<LweCiphertext<T>> {
        let context = self.pbs.resources.context;
        let dimension = context.parameters().external_lwe_dimension();
        let mut outputs = vec![LweCiphertext::zero(dimension.get()); lookup_table.output_count()];
        self.apply_lookup_table_to(input, lookup_table, &mut outputs);
        outputs
    }

    /// Evaluates all factors into caller-owned outputs without allocating.
    ///
    /// # Correctness
    ///
    /// Input must use this context's external secret and unsigned Rounded
    /// encoding, with a message in `0..lookup_table.input_domain_len()`. Input
    /// noise, pre-BR KS (for KB), and coefficient-wise quantization must keep
    /// the rotation in that message's LUT interval. Each integer factor W
    /// amplifies BR noise, including aggregation of all Block selectors and any
    /// dummies. Public FFT multiplication adds phase error
    /// `delta_b - sum(delta_a[j]*s[j])`, followed by output KS and Q→q rounding
    /// for BK. Budget these together: at the returned modulus r, the Scaled
    /// recovery condition is `abs((t*delta-r)*y + t*e) < r/2`, where delta is
    /// the external codec scale and e includes any scale-conversion error.
    /// No noise bound is checked. Decode with a Scaled codec at the external
    /// modulus and the compiled output message modulus.
    ///
    /// # Panics
    ///
    /// Panics before output writes unless the program was prepared by this exact
    /// context, input and every output have the external LWE dimension, and the
    /// output slice length equals the program's output count.
    pub fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &FourierFactorizedLookupTable<'_, T, Table>,
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
            outputs.iter().all(|out| out.dimension() == dimension.get()),
            "MVB output ciphertext dimension mismatch"
        );

        let glwe = parameters.blind_rotation_params();
        let n = glwe.poly_length().get();
        let resources = &mut evaluator.resources;
        resources.blind_rotate(input, &lookup_table.common_polynomial, 1);
        resources
            .accumulator
            .write_fourier_form(&mut self.shared_rotation, &mut resources.fft);
        for (factor, output) in
            FourierPolynomialIter::new(&lookup_table.factors, n / 2).zip(outputs)
        {
            let resources = &mut evaluator.resources;
            // Keep the shared result intact; only one component-sized Fourier
            // product is needed before overwriting its coefficient destination.
            for (component, destination) in
                FourierPolynomialIter::new(self.shared_rotation.as_ref(), n / 2)
                    .zip(resources.accumulator.as_mut().chunks_exact_mut(n))
            {
                component.mul_to(&factor, &mut self.product);
                resources
                    .fft
                    .backward_as_torus(self.product.as_ref(), destination);
            }
            evaluator.return_accumulator_to(core::iter::once(output.as_mut_view()));
        }
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    LM: RingContext<T>,
    Table: FftTable,
{
    /// Creates an MVB evaluator owning its PBS and factor-product workspaces.
    ///
    /// Checks key compatibility once through [`Self::evaluator`]. Context and
    /// key material remain borrowed; online evaluation reuses every buffer.
    /// Inherits [`Evaluator::try_new`]'s material requirements.
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
    ///
    /// # Panics
    /// Panics for coefficient types other than u32/u64, as required by the FFT conversion.
    pub fn compile_mvb_fn<F>(
        &self,
        input_domain_len: usize,
        output_count: usize,
        function: F,
    ) -> Result<FourierFactorizedLookupTable<'_, T, Table>, LookupTableError>
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
    /// Factors use signed integer FFTs, without torus scaling; evaluation requires
    /// this context instance. Inherits [`FourierFactorizedLookupTable::new`]'s
    /// floating-point error limits.
    ///
    /// # Panics
    /// Panics for coefficient types other than u32/u64, as required by the FFT conversion.
    pub fn compile_mvb_fn_with_messages<F>(
        &self,
        messages: crate::PbsMessageConfig<T>,
        input_domain_len: usize,
        output_count: usize,
        function: F,
    ) -> Result<FourierFactorizedLookupTable<'_, T, Table>, LookupTableError>
    where
        F: Fn(usize, usize) -> T,
    {
        let lookup_table =
            self.parameters()
                .compile_mvb_fn(messages, input_domain_len, output_count, function)?;
        Ok(FourierFactorizedLookupTable::new(self, lookup_table))
    }
}
