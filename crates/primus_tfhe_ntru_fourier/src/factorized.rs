//! Prepared factorized MVB programs and their reusable evaluator.

use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_lattice::ntru::FourierNtru;
use primus_modulus::NativeModulus;
use primus_poly::{FourierPolynomial, FourierPolynomialIter, PolynomialIter, PolynomialOwned};
use primus_tfhe::{FactorizedLookupTable, LweCiphertext};

use crate::{Evaluator, LookupTableError, Lwe, ServerKey, TfheContext, TfheEvaluationError};

/// Native even-scale MVB program prepared for one borrowed Fourier context.
///
/// V stays in coefficient form. Factors are stored contiguously as Fourier
/// transforms of signed integers, without torus scaling. Their coefficient
/// storage is discarded after preparation. Context identity protects the FFT
/// layout and ordering, which polynomial length alone cannot establish.
/// The input reducer is used during preparation only; the program retains
/// its domain binding and transformed factors.
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
    /// length, input encoding and coefficient modulus match this context.
    #[must_use]
    pub fn new<LM: primus_reduce::RingContext<T>>(
        context: &'a TfheContext<T, Table, LM>,
        lookup_table: FactorizedLookupTable<T>,
    ) -> Self {
        assert!(
            matches!(T::BITS, 32 | 64),
            "Fourier MVB requires u32 or u64 coefficients"
        );
        let parameters = context.parameters();
        let n = parameters.accumulator_ntru().poly_length().get();
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
        self.factors.len() / self.context.poly_length().fourier_poly_len()
    }

    /// Returns the plaintext modulus of the shared unsigned Scaled output codec.
    #[must_use]
    pub fn output_plaintext_modulus(&self) -> T {
        self.output_plaintext_modulus
    }
}

/// Reusable workspace for Native even-scale NTRU MVB.
///
/// Lifts and blind-rotates V using the selected PBS key at
/// rotation step one, then multiplies each factor. Each product is independently
/// converted Q→q and extracted, then small LWE tiles share key switching to the
/// external secret.
/// Extra workspace consists of two Fourier NTRU polynomials
/// (N complex values), independent of output count. Coefficient products and
/// key switching reuse the ordinary evaluator's buffers and key material.
/// Owns the ordinary evaluator, while borrowing its context and key material.
pub struct FactorizedEvaluator<
    'a,
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T> = NativeModulus<T>,
> {
    pbs: Evaluator<'a, T, Table, LM>,
    shared_rotation: FourierNtru<Vec<Complex64>>,
    product: FourierNtru<Vec<Complex64>>,
}

impl<'a, T: TorusFftValue, Table: FftTable, LM: primus_reduce::RingContext<T>>
    FactorizedEvaluator<'a, T, Table, LM>
{
    /// Takes ownership of a prepared PBS evaluator and allocates two Fourier
    /// polynomials for MVB. Its existing BR/FFT and scalar/batch return buffers
    /// are moved without copying key material or preparing them again.
    /// Both classic and sparse PBS keys use the same factor/return path.
    #[must_use]
    pub fn new(evaluator: Evaluator<'a, T, Table, LM>) -> Self {
        let context = evaluator.resources.context;
        Self {
            pbs: evaluator,
            shared_rotation: FourierNtru::zero(context.poly_length().fourier_poly_len()),
            product: FourierNtru::zero(context.poly_length().fourier_poly_len()),
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
        let dimension = context.external_lwe_dimension();
        let mut outputs = vec![LweCiphertext::zero(dimension.get()); lookup_table.output_count()];
        self.apply_lookup_table_to(input, lookup_table, &mut outputs);
        outputs
    }

    /// Evaluates all factors into caller-owned outputs without allocating.
    ///
    /// # Correctness
    ///
    /// Input must use the server key's external client secret and unsigned Rounded
    /// encoding, with a message in `0..lookup_table.input_domain_len()`. Input
    /// noise and coefficient-wise quantization must keep the rotation in that
    /// message's LUT interval. Each integer factor W amplifies both public-lift
    /// and BR noise, including sparse bucket aggregation. Public FFT multiplication
    /// adds phase error `f_acc * delta_c`; each product then incurs modulus
    /// conversion and LWE key-switch errors.
    /// Before returning, the Scaled recovery condition is
    /// `abs((t*delta-Q)*y + t*e) < Q/2`, Q=2^BITS. Return conversion rescales
    /// delta by q/Q and adds rounding and key-switch errors. Decode using a
    /// Scaled codec at external q with the same plaintext modulus; also budget
    /// the difference between the rescaled delta and round(q/t). No noise bound
    /// is checked.
    ///
    /// # Panics
    ///
    /// Panics before output writes unless the program was prepared by this exact
    /// context, input and every output have the external LWE dimension, and the
    /// output slice length equals the program's output count. A new valid request
    /// supersedes pending samples from an interrupted MVB request.
    pub fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &FourierFactorizedLookupTable<'_, T, Table>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        self.check_io(input.as_view(), lookup_table, outputs);
        self.prepare_shared_rotation(input, &lookup_table.common_polynomial);

        let n = self.pbs.resources.context.poly_length().get();
        let mut factors = FourierPolynomialIter::new(&lookup_table.factors, n / 2);
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
        lookup_table: &FourierFactorizedLookupTable<'_, T, Table>,
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
            outputs.iter().all(|out| out.dimension() == dimension.get()),
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
            .write_fourier_form(&mut self.shared_rotation, &mut resources.fft);
    }

    /// Multiply one factor into the reusable coefficient accumulator.
    /// The caller returns its phase before the next factor overwrites the product.
    fn prepare_factor_product(&mut self, factor: FourierPolynomial<&[Complex64]>) {
        let resources = &mut self.pbs.resources;
        self.shared_rotation
            .mul_fourier_polynomial_to(&factor, &mut self.product);
        self.product
            .write_torus_form(&mut resources.blind_rotation.current, &mut resources.fft);
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
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
    /// Checks the Scaled LUT output at Q and returned output at q before compiling;
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
        let codecs = self.parameters().factorized_pbs_codecs(messages)?;
        let lookup_table = self.parameters().compile_factorized_lookup_table_fn(
            &codecs,
            input_domain_len,
            output_count,
            function,
        )?;
        Ok(FourierFactorizedLookupTable::new(self, lookup_table))
    }
}
