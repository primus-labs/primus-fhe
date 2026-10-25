use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_reduce::{Modulus, PrepareModulusSwitch, ReduceAdd, RingContext};
use primus_shape::PolyLength;

use super::{InterleavedLookupTable, LookupTable, front_half_domain_len};
use crate::LookupTableError;

/// Reusable encoding environment for ordinary rounded-output lookup tables.
///
/// Binds the polynomial length, unsigned input encoding, accumulator modulus and
/// unsigned output codec. Input and output plaintext moduli are independent.
/// The output codec must use the accumulator modulus; a return path that rescales
/// to another modulus needs a decoder at that destination modulus.
///
/// Construction copies only encoding state and allocates nothing. It does not
/// borrow parameters, keys or transform tables. Program-specific capacity and
/// output checks remain in the compilation methods, which allocate the result.
///
/// ```
/// use primus_encoding::RoundedCodec;
/// use primus_modulus::NativeModulus;
/// use primus_tfhe::LookupTableCompiler;
/// use primus_shape::PolyLength;
///
/// let modulus = NativeModulus::<u32>::new();
/// let input_codec = RoundedCodec::new(16, modulus);
/// let output_codec = RoundedCodec::new(8, modulus);
/// let compiler = LookupTableCompiler::try_new(
///     PolyLength::new(32), &input_codec, modulus, &output_codec,
/// )?;
/// let single = compiler.compile_fn(|m| (m % 4) as u32)?;
/// let multiple = compiler.compile_interleaved_fn(2, |m, i| ((m + i) % 8) as u32)?;
/// # Ok::<(), primus_tfhe::LookupTableError>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct LookupTableCompiler<T, IM, M, OM = M>
where
    T: FheUint,
    IM: Modulus<ValueT = T>,
    M: Modulus<ValueT = T>,
    OM: Modulus<ValueT = T>,
{
    poly_length: PolyLength,
    input_plaintext_modulus: T,
    input_ciphertext_modulus: IM,
    coefficient_modulus: M,
    output_codec: RoundedCodec<T, OM>,
}

impl<T, IM, M, OM> LookupTableCompiler<T, IM, M, OM>
where
    T: FheUint,
    IM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
    M: RingContext<T>,
    OM: Modulus<ValueT = T> + ReduceAdd<T, Output = T>,
{
    /// Creates a [`LookupTableCompiler`] from validated codecs.
    ///
    /// Returns [`LookupTableError::OutputModulusMismatch`] if the output codec's
    /// ciphertext modulus differs from `coefficient_modulus`. Polynomial capacity
    /// and rotation-center checks depend on the program and run when compiling.
    pub fn try_new(
        poly_length: PolyLength,
        input_codec: &RoundedCodec<T, IM>,
        coefficient_modulus: M,
        output_codec: &RoundedCodec<T, OM>,
    ) -> Result<Self, LookupTableError> {
        check_output_modulus(coefficient_modulus, output_codec)?;
        Ok(Self {
            poly_length,
            input_plaintext_modulus: input_codec.plaintext_modulus(),
            input_ciphertext_modulus: input_codec.ciphertext_modulus(),
            coefficient_modulus,
            output_codec: *output_codec,
        })
    }

    /// Returns a compiler with a different output codec, keeping the input domain
    /// and accumulator modulus. Rejects a mismatched ciphertext modulus here,
    /// before any program is compiled. The supplied codec is copied.
    pub fn try_with_output_codec<NM>(
        self,
        output_codec: &RoundedCodec<T, NM>,
    ) -> Result<LookupTableCompiler<T, IM, M, NM>, LookupTableError>
    where
        NM: Modulus<ValueT = T> + ReduceAdd<T, Output = T>,
    {
        check_output_modulus(self.coefficient_modulus, output_codec)?;
        Ok(LookupTableCompiler {
            poly_length: self.poly_length,
            input_plaintext_modulus: self.input_plaintext_modulus,
            input_ciphertext_modulus: self.input_ciphertext_modulus,
            coefficient_modulus: self.coefficient_modulus,
            output_codec: *output_codec,
        })
    }

    /// Compiles one function over the entire front half `0..ceil(t_in/2)`.
    ///
    /// Outputs must be in `0..t_out` and are encoded unsigned with the bound
    /// output codec. On success the callback runs once per input in increasing
    /// order. Encoding and capacity checks precede callbacks; center collisions
    /// and output-range errors stop compilation during filling.
    /// See [`LookupTable::try_new`] for the rotation and layout contract.
    pub fn compile_fn<F>(&self, function: F) -> Result<LookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        let domain_len = front_half_domain_len(self.input_plaintext_modulus)?;
        self.compile_single(domain_len, function)
    }

    /// Slice form of [`Self::compile_fn`], with one value per front-half input.
    /// Length errors precede filling and output-value validation.
    pub fn compile_slice(&self, outputs: &[T]) -> Result<LookupTable<T>, LookupTableError> {
        let domain_len = front_half_domain_len(self.input_plaintext_modulus)?;
        check_output_length(outputs.len(), domain_len)?;
        self.compile_single(domain_len, |input| outputs[input])
    }

    /// Compiles all inputs `0..t_in` for odd `t_in`, encoding outputs as in
    /// [`Self::compile_fn`]. The callback runs once per input in folded-center
    /// order: `0, (t_in+1)/2, 1, (t_in+3)/2, ...`.
    /// See [`LookupTable::try_new_odd_full_domain`] for capacity and noise requirements.
    pub fn compile_odd_full_domain_fn<F>(
        &self,
        function: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        LookupTable::try_new_odd_full_domain(
            self.poly_length,
            self.input_plaintext_modulus,
            self.input_ciphertext_modulus,
            self.coefficient_modulus,
            |input| self.encode_output(function(input), input),
        )
    }

    /// Slice form of [`Self::compile_odd_full_domain_fn`]. Supply exactly
    /// `t_in` outputs in plaintext input order. Length errors precede compilation.
    pub fn compile_odd_full_domain_slice(
        &self,
        outputs: &[T],
    ) -> Result<LookupTable<T>, LookupTableError> {
        let expected = self
            .input_plaintext_modulus
            .try_into()
            .map_err(|_| LookupTableError::PlaintextModulusTooLarge)?;
        check_output_length(outputs.len(), expected)?;
        self.compile_odd_full_domain_fn(|input| outputs[input])
    }

    /// Compiles `output_count` functions over the entire front-half input domain.
    ///
    /// The callback receives `(input, output_index)`, visiting inputs in increasing
    /// order and outputs in `0..output_count` for each input. Outputs follow
    /// [`Self::compile_fn`]. The output count must be nonzero; padded lanes are
    /// zero. See [`InterleavedLookupTable::try_new`] for capacity and reduced
    /// rotation resolution. Encoding and capacity checks precede callbacks;
    /// center collisions and output ranges are checked during filling.
    pub fn compile_interleaved_fn<F>(
        &self,
        output_count: usize,
        function: F,
    ) -> Result<InterleavedLookupTable<T>, LookupTableError>
    where
        F: Fn(usize, usize) -> T,
    {
        let domain_len = front_half_domain_len(self.input_plaintext_modulus)?;
        self.compile_interleaved(domain_len, output_count, function)
    }

    /// Slice form of [`Self::compile_interleaved_fn`]. Supply
    /// `ceil(t_in/2) * output_count` values ordered by input, then output index.
    /// Length errors precede filling and output-value validation.
    pub fn compile_interleaved_slice(
        &self,
        output_count: usize,
        outputs: &[T],
    ) -> Result<InterleavedLookupTable<T>, LookupTableError> {
        let domain_len = front_half_domain_len(self.input_plaintext_modulus)?;
        let expected = domain_len
            .checked_mul(output_count)
            .ok_or(LookupTableError::TableLengthOverflow)?;
        check_output_length(outputs.len(), expected)?;
        self.compile_interleaved(domain_len, output_count, |input, output| {
            outputs[input * output_count + output]
        })
    }

    // Both fn/slice paths supply a checked domain length. Keep output encoding
    // inside the existing raw compiler's callback to preserve first-error order.
    fn compile_single<F>(
        &self,
        domain_len: usize,
        function: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        LookupTable::try_new(
            domain_len,
            self.poly_length,
            self.input_plaintext_modulus,
            self.input_ciphertext_modulus,
            self.coefficient_modulus,
            |input| self.encode_output(function(input), input),
        )
    }

    // The raw compiler fills input-major output groups directly in the result;
    // encoding here needs no temporary polynomial or per-output allocation.
    fn compile_interleaved<F>(
        &self,
        domain_len: usize,
        output_count: usize,
        function: F,
    ) -> Result<InterleavedLookupTable<T>, LookupTableError>
    where
        F: Fn(usize, usize) -> T,
    {
        InterleavedLookupTable::try_new(
            domain_len,
            self.poly_length,
            output_count,
            self.input_plaintext_modulus,
            self.input_ciphertext_modulus,
            self.coefficient_modulus,
            |input, output| self.encode_output(function(input, output), input),
        )
    }

    #[inline]
    fn encode_output(&self, output: T, input: usize) -> Result<T, LookupTableError> {
        if output >= self.output_codec.plaintext_modulus() {
            return Err(LookupTableError::OutputOutOfRange { input });
        }
        Ok(self
            .output_codec
            .encode_value(output, PlaintextEmbedding::Unsigned))
    }
}

fn check_output_length(actual: usize, expected: usize) -> Result<(), LookupTableError> {
    if actual != expected {
        return Err(LookupTableError::DomainLengthMismatch { expected, actual });
    }
    Ok(())
}

fn check_output_modulus<T, M, OM>(
    modulus: M,
    codec: &RoundedCodec<T, OM>,
) -> Result<(), LookupTableError>
where
    T: FheUint,
    M: Modulus<ValueT = T>,
    OM: Modulus<ValueT = T> + ReduceAdd<T, Output = T>,
{
    if codec.ciphertext_modulus().explicit_value() != modulus.explicit_value() {
        return Err(LookupTableError::OutputModulusMismatch);
    }
    Ok(())
}
