use primus_integer::FheUint;
use primus_modulus::UintModulus;
use primus_reduce::{Modulus, ModulusSwitch, PrepareModulusSwitch};

/// Prepared `q -> t` decoding shared by [`crate::RoundedCodec`] and
/// [`crate::ScaledCodec`]. Construct with `MessageDecoder::from(&codec)` to copy
/// the codec's prepared state without allocation or preparing another switch.
///
/// Decoding rounds `value * t / q` to the nearest integer, ties upward, modulo
/// `t`. Sharing this rule does not equate the codecs' encoding centers or noise
/// margins; recovery still requires the producing operation's error bound.
#[derive(Clone, Copy, Debug)]
pub struct MessageDecoder<T: FheUint, M: Modulus<ValueT = T>> {
    plaintext_modulus: T,
    ciphertext_modulus: M,
    switch: ModulusSwitch<T>,
}

impl<T: FheUint, M: Modulus<ValueT = T>> MessageDecoder<T, M> {
    /// The owning codec has already validated `t >= 2` and `q > t`.
    pub(super) fn from_validated_moduli(plaintext_modulus: T, ciphertext_modulus: M) -> Self
    where
        M: PrepareModulusSwitch,
    {
        Self {
            plaintext_modulus,
            ciphertext_modulus,
            switch: ciphertext_modulus.prepare_switch_to(UintModulus(plaintext_modulus)),
        }
    }

    /// Returns the decoded message modulus `t`.
    #[must_use]
    #[inline]
    pub fn plaintext_modulus(&self) -> T {
        self.plaintext_modulus
    }

    /// Returns the ciphertext modulus `q` expected by this decoder.
    #[must_use]
    #[inline]
    pub fn ciphertext_modulus(&self) -> M {
        self.ciphertext_modulus
    }

    /// Decodes a ciphertext residue into a canonical message in `[0, t)`.
    ///
    /// # Correctness
    /// `value` must be in `[0, q)`. This range is not checked.
    #[must_use]
    #[inline]
    pub fn decode_value(&self, value: T) -> T {
        self.switch.switch(value)
    }

    /// Replaces ciphertext residues with canonical messages in `[0, t)`.
    ///
    /// # Correctness
    /// Every input must be in `[0, q)`. This range is not checked.
    #[inline]
    pub fn decode_slice_assign(&self, values: &mut [T]) {
        self.switch
            .switch_map(values.iter_mut().map(|out| (*out, out)), |value, out| {
                *out = value
            });
    }

    /// Decodes into an equally sized output slice of canonical messages in `[0, t)`.
    ///
    /// # Correctness
    /// Every input must be in `[0, q)`. This range is not checked.
    ///
    /// # Panics
    /// Panics if the slices differ in length, before writing any output.
    #[inline]
    pub fn decode_slice_to(&self, input: &[T], output: &mut [T]) {
        assert_eq!(input.len(), output.len(), "decoding slice length mismatch");
        self.switch
            .switch_map(input.iter().copied().zip(output), |value, out| *out = value);
    }
}
