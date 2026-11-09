//! Message choices and codec preparation, independent of keys and transforms.

use primus_encoding::{RoundedCodec, ScaledCodec};
use primus_integer::FheUint;
use primus_reduce::RingContext;

use crate::LookupTableError;

/// Input and output plaintext moduli for ordinary PBS, ManyLUT or factorized MVB.
///
/// [`Self::new`] selects equal moduli; [`Self::with_output_modulus`] changes only
/// the output domain. These are message moduli, not ciphertext q/Q. Validation
/// happens when preparing codecs, after all choices have been supplied.
/// Keys, input padding, LUT capacity and noise budgets are independent choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PbsMessageConfig<T: FheUint> {
    /// Input plaintext modulus `t_in`; front-half inputs use `0..ceil(t_in/2)`.
    pub input_modulus: T,
    /// Common output plaintext modulus `t_out`; results belong to `0..t_out`.
    pub output_modulus: T,
}

impl<T: FheUint> PbsMessageConfig<T> {
    /// Chooses the same plaintext modulus for input and all outputs.
    #[must_use]
    pub const fn new(plaintext_modulus: T) -> Self {
        Self {
            input_modulus: plaintext_modulus,
            output_modulus: plaintext_modulus,
        }
    }

    /// Chooses a padded input domain of `2^input_bits` values and equal codec moduli.
    ///
    /// The codec modulus is `2^(input_bits+1)`: one extra bit provides the
    /// ordinary PBS padding. The full output domain has that same modulus;
    /// output padding and reconsumption are not implied. Zero input bits describe
    /// the singleton domain. Ciphertext-modulus and LUT-capacity checks remain
    /// with codec preparation and program compilation.
    ///
    /// # Panics
    /// Panics if the codec modulus does not fit the coefficient word.
    #[must_use]
    pub fn from_input_bits(input_bits: u32) -> Self {
        Self::try_from_input_bits(input_bits).unwrap_or_else(|error| panic!("{error}"))
    }

    /// Prepares the padded message choice described by [`Self::from_input_bits`].
    /// Returns [`LookupTableError::InvalidInputEncoding`] if the codec modulus
    /// does not fit the word. This does not validate a noise or security budget.
    pub fn try_from_input_bits(input_bits: u32) -> Result<Self, LookupTableError> {
        if input_bits >= T::BITS - 1 {
            return Err(LookupTableError::InvalidInputEncoding);
        }
        Ok(Self::new(T::ONE << (input_bits + 1)))
    }

    /// Changes the output plaintext modulus without changing the input domain.
    #[must_use]
    pub const fn with_output_modulus(mut self, plaintext_modulus: T) -> Self {
        self.output_modulus = plaintext_modulus;
        self
    }

    /// Prepares Rounded codecs for ordinary PBS and ManyLUT.
    ///
    /// Input and returned ciphertexts use `external_modulus` (q); the LUT uses
    /// `accumulator_modulus` (Q). Both output codecs derive from `output_modulus`.
    /// Returns input/output encoding errors before any LUT or key is generated.
    /// Family parameter factories supply q/Q automatically.
    pub fn try_rounded_codecs<M, LM>(
        self,
        external_modulus: LM,
        accumulator_modulus: M,
    ) -> Result<RoundedPbsCodecs<T, M, LM>, LookupTableError>
    where
        M: RingContext<T>,
        LM: RingContext<T>,
    {
        Ok(PbsCodecs {
            input_codec: RoundedCodec::try_new(self.input_modulus, external_modulus)
                .map_err(LookupTableError::InputEncoding)?,
            lut_output_codec: RoundedCodec::try_new(self.output_modulus, accumulator_modulus)?,
            output_codec: RoundedCodec::try_new(self.output_modulus, external_modulus)?,
        })
    }

    /// Prepares Rounded input and Scaled outputs for factorized MVB.
    ///
    /// Both output codecs derive from the same `output_modulus`, at accumulator
    /// Q for the LUT and external q for returned ciphertexts. Each Scaled codec
    /// must satisfy its own domain and scale-recovery conditions. This does not
    /// prove recovery after Q→q rounding and key switching; budget those errors
    /// separately. Factorization modulus/scale and capacity checks remain in
    /// [`crate::FactorizedLookupTable::try_new`].
    pub fn try_factorized_codecs<M, LM>(
        self,
        external_modulus: LM,
        accumulator_modulus: M,
    ) -> Result<FactorizedPbsCodecs<T, M, LM>, LookupTableError>
    where
        M: RingContext<T>,
        LM: RingContext<T>,
    {
        Ok(PbsCodecs {
            input_codec: RoundedCodec::try_new(self.input_modulus, external_modulus)
                .map_err(LookupTableError::InputEncoding)?,
            lut_output_codec: ScaledCodec::try_new(self.output_modulus, accumulator_modulus)?,
            output_codec: ScaledCodec::try_new(self.output_modulus, external_modulus)?,
        })
    }
}

/// Prepared input, LUT-output and returned-output codecs from one message config.
///
/// The two outputs share a plaintext modulus, but may use different ciphertext
/// moduli. The concrete codec types preserve Rounded/Scaled distinctions without
/// runtime dispatch. Preparation allocates nothing and retains no key, parameter,
/// transform table or workspace borrow. Equal input/output moduli do not prove
/// that an output fits the input domain or noise margin of a subsequent PBS.
#[derive(Clone, Copy, Debug)]
pub struct PbsCodecs<Input, LutOutput, Output = LutOutput> {
    input_codec: Input,
    lut_output_codec: LutOutput,
    output_codec: Output,
}

/// Rounded input and outputs for ordinary PBS and ManyLUT; M is Q and LM is q.
pub type RoundedPbsCodecs<T, M, LM = M> =
    PbsCodecs<RoundedCodec<T, LM>, RoundedCodec<T, M>, RoundedCodec<T, LM>>;

/// Rounded input and Scaled outputs for factorized MVB; M is Q and LM is q.
pub type FactorizedPbsCodecs<T, M, LM = M> =
    PbsCodecs<RoundedCodec<T, LM>, ScaledCodec<T, M>, ScaledCodec<T, LM>>;

impl<Input, LutOutput, Output> PbsCodecs<Input, LutOutput, Output> {
    /// Returns the input codec at the external ciphertext modulus q.
    #[must_use]
    pub fn input_codec(&self) -> &Input {
        &self.input_codec
    }

    /// Returns the output codec used to compile the LUT at accumulator modulus Q.
    #[must_use]
    pub fn lut_output_codec(&self) -> &LutOutput {
        &self.lut_output_codec
    }

    /// Returns the output codec for decoding returned ciphertexts at external q.
    /// Pass this codec to the context's `decryptor` factory for `decrypt()` with
    /// the selected output message modulus, including Scaled MVB outputs.
    /// The returned phase still includes any Q→q rounding and return-stage noise.
    #[must_use]
    pub fn output_codec(&self) -> &Output {
        &self.output_codec
    }
}
