use primus_integer::FheUint;
use primus_reduce::Modulus;

use crate::CodecError;

#[inline]
pub(super) fn centered_negative_start<T: FheUint>(plaintext_modulus: T) -> T {
    (plaintext_modulus >> 1u32) + (plaintext_modulus & T::ONE)
}

/// Returns the magnitude and negative flag of the centered lift.
///
/// # Correctness
///
/// Requires `t = plaintext_modulus >= 2`, `message < t`, and
/// `negative_start = ceil(t/2)`. A negative lift then has strictly positive
/// magnitude, including `1 -> -1` for `t = 2`.
#[inline]
pub(super) fn lift_centered_from_raw<T: FheUint>(
    message: T,
    plaintext_modulus: T,
    negative_start: T,
) -> (T, bool) {
    if message < negative_start {
        (message, false)
    } else {
        (plaintext_modulus - message, true)
    }
}

#[inline]
pub(super) fn check_message<T: FheUint>(message: T, plaintext_modulus: T) {
    assert!(
        message < plaintext_modulus,
        "message outside plaintext domain"
    );
}

/// Validates the encoding domain before preparing either modulus conversion.
pub(super) fn validate_moduli<T, M>(
    plaintext_modulus: T,
    ciphertext_modulus: M,
) -> Result<(), CodecError>
where
    T: FheUint,
    M: Modulus<ValueT = T>,
{
    if plaintext_modulus < T::TWO {
        return Err(CodecError::InvalidPlaintextModulus);
    }
    if ciphertext_modulus
        .explicit_value()
        .is_some_and(|q| q <= plaintext_modulus)
    {
        return Err(CodecError::CiphertextModulusTooSmall);
    }
    Ok(())
}
