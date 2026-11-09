use super::helpers;
use super::helpers::{check_message, lift_centered_from_raw};
use crate::{MessageDecoder, PlaintextEmbedding};
use primus_integer::FheUint;
use primus_modulus::UintModulus;
use primus_reduce::{Modulus, ModulusSwitch, PrepareModulusSwitch, ReduceAdd};

/// Per-message rounding: `round(lift(m) * q / t) mod q`, returned in `[0,q)`,
/// with ties away from zero before modular reduction.
/// Decoding rounds `c * t / q` to the nearest integer, ties upward, modulo `t`.
/// Inputs to decoding and accumulators must be canonical residues in `[0,q)`.
///
/// This keeps modulus-shape checks and shift/mask computation out of hot
/// coefficient loops while hiding strategy-specific precomputation.
#[derive(Clone, Copy, Debug)]
pub struct RoundedCodec<T: FheUint, M: Modulus<ValueT = T>> {
    decoder: MessageDecoder<T, M>,
    /// First canonical plaintext representative interpreted as negative: `ceil(t/2)`.
    centered_negative_start: T,
    /// Prepared `t -> q` conversion for unsigned messages or centered magnitudes.
    encoding_switch: ModulusSwitch<T>,
}

impl<T, M> RoundedCodec<T, M>
where
    T: FheUint,
    M: ReduceAdd<T, Output = T> + Modulus<ValueT = T>,
{
    /// Creates a codec for plaintext modulus `t` and ciphertext modulus `q`.
    ///
    /// `NativeModulus<T>` selects the native wrapping modulus `2^T::BITS`.
    ///
    /// # Panics
    ///
    /// Panics if `t <= 1` or an explicit `q` is not greater than `t`.
    #[must_use]
    #[inline]
    pub fn new(plaintext_modulus: T, ciphertext_modulus: M) -> Self
    where
        M: PrepareModulusSwitch,
    {
        Self::try_new(plaintext_modulus, ciphertext_modulus)
            .unwrap_or_else(|error| panic!("{error}"))
    }

    /// Prepares encoding/decoding after checking `t >= 2` and `q > t`.
    /// Returns the invalid domain as a [`crate::CodecError`].
    pub fn try_new(plaintext_modulus: T, ciphertext_modulus: M) -> Result<Self, crate::CodecError>
    where
        M: PrepareModulusSwitch,
    {
        helpers::validate_moduli(plaintext_modulus, ciphertext_modulus)?;
        let plaintext_modulus_context = UintModulus(plaintext_modulus);
        Ok(Self {
            decoder: MessageDecoder::from_validated_moduli(plaintext_modulus, ciphertext_modulus),
            centered_negative_start: helpers::centered_negative_start(plaintext_modulus),
            encoding_switch: plaintext_modulus_context.prepare_switch_to(ciphertext_modulus),
        })
    }

    /// Returns the plaintext modulus `t` used by this codec.
    #[must_use]
    #[inline]
    pub fn plaintext_modulus(&self) -> T {
        self.decoder.plaintext_modulus()
    }

    /// Returns the ciphertext modulus used for encoding and decoding.
    #[must_use]
    #[inline]
    pub fn ciphertext_modulus(&self) -> M {
        self.decoder.ciphertext_modulus()
    }
}

impl<T, M> RoundedCodec<T, M>
where
    T: FheUint,
    M: ReduceAdd<T, Output = T> + Modulus<ValueT = T>,
{
    /// Decodes a ciphertext residue into a canonical plaintext residue in `[0,t)`.
    ///
    /// # Correctness
    ///
    /// `value` must be in `[0,q)`. This range is not checked.
    #[must_use]
    #[inline]
    pub fn decode_value(&self, value: T) -> T {
        self.decoder.decode_value(value)
    }

    /// Replaces ciphertext residues with canonical plaintext residues in `[0,t)`.
    ///
    /// # Correctness
    ///
    /// Every input must be in `[0,q)`. This range is not checked.
    #[inline]
    pub fn decode_slice_assign(&self, values: &mut [T]) {
        self.decoder.decode_slice_assign(values);
    }

    /// Decodes into an equally sized output slice of canonical residues in `[0,t)`.
    ///
    /// # Correctness
    ///
    /// Every input must be in `[0,q)`. This range is not checked.
    ///
    /// # Panics
    ///
    /// Panics if the slices differ in length, before writing any output.
    #[inline]
    pub fn decode_slice_to(&self, input: &[T], output: &mut [T]) {
        self.decoder.decode_slice_to(input, output);
    }
}

impl<T, M> RoundedCodec<T, M>
where
    T: FheUint,
    M: ReduceAdd<T, Output = T> + Modulus<ValueT = T>,
{
    /// Encodes a message in `[0,t)` into a canonical ciphertext residue in `[0,q)`.
    ///
    /// # Panics
    ///
    /// Panics if the message lies outside the plaintext domain `[0,t)`.
    #[must_use]
    #[inline]
    pub fn encode_value(&self, message: T, embedding: PlaintextEmbedding) -> T {
        check_message(message, self.plaintext_modulus());
        let mut output = T::ZERO;
        self.encode::<false, _>(core::iter::once((&mut output, message)), embedding);
        output
    }

    /// Encodes `messages` into canonical residues in `output` using the selected embedding.
    /// The previous output is overwritten; validation completes before any writes.
    ///
    /// # Panics
    ///
    /// Panics if the slices differ in length or a message lies outside the
    /// plaintext domain `[0,t)`.
    #[inline]
    pub fn encode_slice_to(&self, messages: &[T], output: &mut [T], embedding: PlaintextEmbedding) {
        self.validate(messages, output.len());
        self.encode::<false, _>(output.iter_mut().zip(messages.iter().copied()), embedding);
    }

    /// Replaces plaintext residues with canonical ciphertext residues using the
    /// selected embedding. Validation completes before any writes.
    ///
    /// # Panics
    ///
    /// Panics if a value lies outside the plaintext domain `[0,t)`.
    #[inline]
    pub fn encode_slice_assign(&self, values: &mut [T], embedding: PlaintextEmbedding) {
        self.validate(values, values.len());
        self.encode::<false, _>(
            values.iter_mut().map(|out| {
                let message = *out;
                (out, message)
            }),
            embedding,
        );
    }
}

impl<T, M> RoundedCodec<T, M>
where
    T: FheUint,
    M: ReduceAdd<T, Output = T> + Modulus<ValueT = T>,
{
    /// Encodes `message` and adds it modulo `q` to `accumulator` without clearing it.
    ///
    /// # Correctness
    ///
    /// `accumulator` must be in `[0,q)` and remains canonical after the addition.
    /// Its range is not checked.
    ///
    /// # Panics
    ///
    /// Panics if the message is outside `[0,t)`.
    #[inline]
    pub fn add_encode_value_assign(
        &self,
        accumulator: &mut T,
        message: T,
        embedding: PlaintextEmbedding,
    ) {
        check_message(message, self.plaintext_modulus());
        self.encode::<true, _>(core::iter::once((accumulator, message)), embedding);
    }

    /// Encodes each message and adds it modulo `q` to the corresponding accumulator.
    /// The accumulator is not cleared; message validation completes before any writes.
    ///
    /// # Correctness
    ///
    /// Every accumulator must be in `[0,q)` and remains canonical after addition.
    /// Accumulator ranges are not checked.
    ///
    /// # Panics
    ///
    /// Panics on a length mismatch or a message outside `[0,t)`.
    #[inline]
    pub fn add_encode_slice_assign(
        &self,
        accumulator: &mut [T],
        messages: &[T],
        embedding: PlaintextEmbedding,
    ) {
        self.validate(messages, accumulator.len());
        self.encode::<true, _>(
            accumulator.iter_mut().zip(messages.iter().copied()),
            embedding,
        );
    }
}

impl<T, M> RoundedCodec<T, M>
where
    T: FheUint,
    M: Modulus<ValueT = T> + ReduceAdd<T, Output = T>,
{
    fn validate(&self, messages: &[T], output_len: usize) {
        assert_eq!(messages.len(), output_len, "encoding slice length mismatch");
        assert!(
            messages
                .iter()
                .copied()
                .max()
                .is_none_or(|m| m < self.plaintext_modulus()),
            "message outside plaintext domain"
        );
    }

    /// The caller validates messages and, for ADD, supplies canonical accumulators.
    /// A negative lift has nonzero magnitude; q > t makes its encoding nonzero.
    /// Carrying sign/output through switch_map keeps arithmetic dispatch outside
    /// the loop and fuses the final write or modular addition.
    #[inline]
    fn encode<'a, const ADD: bool, I>(&self, input: I, embedding: PlaintextEmbedding)
    where
        I: Iterator<Item = (&'a mut T, T)>,
        T: 'a,
    {
        let write = |value, out: &mut T| {
            *out = if ADD {
                self.ciphertext_modulus().reduce_add(*out, value)
            } else {
                value
            };
        };
        match embedding {
            PlaintextEmbedding::Unsigned => {
                self.encoding_switch
                    .switch_map(input.map(|(out, m)| (m, out)), write);
            }
            PlaintextEmbedding::Centered => {
                self.encoding_switch.switch_map(
                    input.map(|(out, m)| {
                        let (magnitude, negative) = lift_centered_from_raw(
                            m,
                            self.plaintext_modulus(),
                            self.centered_negative_start,
                        );
                        (magnitude, (negative, out))
                    }),
                    |value, (negative, out)| {
                        let value = if negative {
                            self.ciphertext_modulus().minus_one() - value + T::ONE
                        } else {
                            value
                        };
                        write(value, out);
                    },
                );
            }
        }
    }
}

impl<T: FheUint, M: Modulus<ValueT = T>> From<&RoundedCodec<T, M>> for MessageDecoder<T, M> {
    fn from(codec: &RoundedCodec<T, M>) -> Self {
        codec.decoder
    }
}
