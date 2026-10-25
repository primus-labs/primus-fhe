use super::{
    helpers::{check_message, lift_centered_from_raw, validate_moduli},
    integer_scale::IntegerScale,
};
use crate::{CodecError, MessageDecoder, PlaintextEmbedding};
use primus_integer::FheUint;
use primus_modulus::UintModulus;
use primus_reduce::{Modulus, PrepareModulusSwitch, ReduceAdd};

/// Fixed rounded scaling: `lift(m) * delta mod q`, returned in `[0,q)`, where
/// `delta = round(q/t)` with ties upward.
///
/// This preserves the coefficient scaling used by single-modulus GLWE/NTRU.
/// It is distinct from BFV's `floor(Q/t)` scaling and per-message rounding.
/// Decoding rounds `c*t/q` with ties upward, modulo `t`. For integer lift `m` and noise `e`,
/// recovery is guaranteed when `abs((t*delta-q)*m + t*e) < q/2`.
/// Accumulators and decoding inputs must be canonical ciphertext residues.
#[derive(Clone, Copy, Debug)]
pub struct ScaledCodec<T: FheUint, M: Modulus<ValueT = T>> {
    decoder: MessageDecoder<T, M>,
    scale: IntegerScale<T>,
}

impl<T, M> ScaledCodec<T, M>
where
    T: FheUint,
    M: ReduceAdd<T, Output = T> + Modulus<ValueT = T>,
{
    /// Constructs a fixed-scale codec for plaintext modulus `t` and ciphertext
    /// modulus `q`; `NativeModulus<T>` denotes `q = 2^T::BITS`.
    ///
    /// The scale-recovery bound below is a conservative sufficient condition
    /// for noiseless recovery with either lift.
    ///
    /// # Panics
    ///
    /// Panics unless `t >= 2`, `q > t`, and
    /// `abs(t*round(q/t)-q)*(t-1) < q/2`.
    #[must_use]
    pub fn new(plaintext_modulus: T, ciphertext_modulus: M) -> Self
    where
        M: PrepareModulusSwitch,
    {
        Self::try_new(plaintext_modulus, ciphertext_modulus)
            .unwrap_or_else(|error| panic!("{error}"))
    }

    /// Prepares fixed-scale encoding after checking the domain and the
    /// noiseless recovery bound documented on [`Self::new`].
    /// This does not establish a noise or security budget.
    pub fn try_new(plaintext_modulus: T, ciphertext_modulus: M) -> Result<Self, CodecError>
    where
        M: PrepareModulusSwitch,
    {
        validate_moduli(plaintext_modulus, ciphertext_modulus)?;
        validate_scale_recovery(plaintext_modulus, ciphertext_modulus)?;
        let plaintext_modulus_context = UintModulus(plaintext_modulus);
        // Preparing from UintModulus validates both moduli before calling M's implementation.
        let delta = plaintext_modulus_context
            .prepare_switch_to(ciphertext_modulus)
            .switch(T::ONE);
        let scale = IntegerScale::new(delta);
        Ok(Self {
            decoder: MessageDecoder::from_validated_moduli(plaintext_modulus, ciphertext_modulus),
            scale,
        })
    }

    /// Returns the plaintext modulus.
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

    /// Encodes a residue in `[0,t)` into a canonical residue in `[0,q)` with the selected lift.
    ///
    /// # Panics
    ///
    /// Panics if the message is outside `[0,t)`.
    #[must_use]
    #[inline]
    pub fn encode_value(&self, message: T, embedding: PlaintextEmbedding) -> T {
        check_message(message, self.plaintext_modulus());
        self.encode_raw(message, embedding)
    }

    /// Encodes a validated plaintext residue `message < t`.
    /// The positive scale and `(t-1)*delta < q` ensure that negative lifts have
    /// nonzero encodings, permitting explicit negation as `q - value`.
    #[inline]
    fn encode_raw(&self, message: T, embedding: PlaintextEmbedding) -> T {
        let (m, negative) = match embedding {
            PlaintextEmbedding::Unsigned => (message, false),
            PlaintextEmbedding::Centered => lift_centered_from_raw(
                message,
                self.plaintext_modulus(),
                super::helpers::centered_negative_start(self.plaintext_modulus()),
            ),
        };
        let value = self.scale.encode_magnitude(m);
        if negative {
            self.scale.neg_nonzero(value, self.ciphertext_modulus())
        } else {
            value
        }
    }

    /// Encodes messages into an equally sized output slice of canonical residues in `[0,q)`.
    /// The previous output is overwritten; validation completes before any writes.
    ///
    /// # Panics
    ///
    /// Panics on a length mismatch or messages outside `[0,t)`.
    #[inline]
    pub fn encode_slice_to(&self, messages: &[T], output: &mut [T], embedding: PlaintextEmbedding) {
        self.validate(messages, output.len());
        self.scale.apply::<false, _, _>(
            output.iter_mut().zip(messages.iter().copied()),
            self.plaintext_modulus(),
            embedding,
            self.ciphertext_modulus(),
        );
    }

    /// Replaces plaintext residues with canonical ciphertext residues in `[0,q)`.
    /// Validation completes before any writes.
    ///
    /// # Panics
    ///
    /// Panics on messages outside `[0,t)`.
    #[inline]
    pub fn encode_slice_assign(&self, values: &mut [T], embedding: PlaintextEmbedding) {
        self.validate(values, values.len());
        self.scale.apply::<false, _, _>(
            values.iter_mut().map(|out| {
                let m = *out;
                (out, m)
            }),
            self.plaintext_modulus(),
            embedding,
            self.ciphertext_modulus(),
        );
    }

    /// Adds encoded messages modulo `q` to the accumulator without clearing it.
    /// Validation of messages and lengths completes before any writes.
    ///
    /// # Correctness
    ///
    /// Every accumulator must be in `[0,q)` and remains canonical after addition.
    /// Accumulator ranges are not checked.
    ///
    /// # Panics
    ///
    /// Panics on a length mismatch or messages outside `[0,t)`.
    #[inline]
    pub fn add_encode_slice_assign(
        &self,
        accumulator: &mut [T],
        messages: &[T],
        embedding: PlaintextEmbedding,
    ) {
        self.validate(messages, accumulator.len());
        self.scale.apply::<true, _, _>(
            accumulator.iter_mut().zip(messages.iter().copied()),
            self.plaintext_modulus(),
            embedding,
            self.ciphertext_modulus(),
        );
    }

    #[inline]
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
    pub fn decode_slice_to(&self, input: &[T], output: &mut [T]) {
        self.decoder.decode_slice_to(input, output);
    }
}

/// Checks a sufficient bound for noiseless recovery under both plaintext embeddings.
/// The caller has already validated `t = plaintext_modulus >= 2` and `q > t`.
///
/// For `delta = round(q/t)` and `epsilon = t*delta-q`, decoding `m*delta` rounds
/// `m + m*epsilon/q` modulo `t`. Since either lift has `abs(m) <= t-1`, the strict
/// bound `abs(epsilon)*(t-1) < q/2` keeps every message inside its rounding cell.
/// This reserves no particular noise budget; noise adds `t*e` to the error.
///
/// It also gives `(t-1)*delta < q`, as required by `IntegerScale`: this is immediate
/// for `epsilon <= 0`; otherwise `epsilon*(t-1) < q = t*delta-epsilon` implies
/// `epsilon < delta`, hence `(t-1)*delta = q+epsilon-delta < q`.
fn validate_scale_recovery<T, M>(
    plaintext_modulus: T,
    ciphertext_modulus: M,
) -> Result<(), CodecError>
where
    T: FheUint,
    M: Modulus<ValueT = T>,
{
    // For q = a*t+r, nearest-integer scaling gives abs(epsilon) = min(r, t-r).
    // Compute r via q-1 so Native q = 2^T::BITS need not be represented in T.
    let remainder = ciphertext_modulus.minus_one() % plaintext_modulus + T::ONE;
    let remainder = if remainder == plaintext_modulus {
        T::ZERO
    } else {
        remainder
    };
    let scale_error = remainder.min(plaintext_modulus - remainder);
    let (max_error, high) = scale_error.carrying_mul(plaintext_modulus - T::ONE, T::ZERO);
    // The product must be below q/2 <= 2^(BITS-1), so a nonzero high word fails.
    // For explicit q, integer error < q/2 is exactly error <= floor((q-1)/2).
    let within_rounding_radius = high == T::ZERO
        && match ciphertext_modulus.explicit_value() {
            Some(q) => max_error <= (q - T::ONE) / T::TWO,
            None => max_error < (T::ONE << (T::BITS - 1)),
        };
    if !within_rounding_radius {
        return Err(CodecError::InsufficientScaleRecovery);
    }
    Ok(())
}

impl<T: FheUint, M: Modulus<ValueT = T>> From<&ScaledCodec<T, M>> for MessageDecoder<T, M> {
    fn from(codec: &ScaledCodec<T, M>) -> Self {
        codec.decoder
    }
}
