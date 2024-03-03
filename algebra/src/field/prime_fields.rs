//! This place defines some concrete implement of the prime field.

use super::Field;

/// A trait specifying a [`Field`] that is also a prime field.
///
/// A prime field is a special type of field with a characteristic that is a prime number.
/// This trait ensures that the implementing type adheres to the mathematical properties
/// of a prime field. Prime fields are widely used in cryptography due to their simplicity
/// and the security properties they offer, such as a high degree of randomness and uniformity
/// in the distribution of elements.
///
/// Types implementing [`PrimeField`] must be capable of determining whether they indeed represent
/// a prime field, typically by checking if their modulus is a prime number, which is a fundamental
/// requirement for a field to be a prime field.
///
/// This trait is important for cryptographic algorithms that require a prime field, such as those
/// found in elliptic curve cryptography and various other cryptographic schemes where the security
/// assumptions are based on the difficulty of solving problems within a prime field.
pub trait PrimeField: Field {
    /// Check if this [`PrimeField`] is a prime field.
    fn is_prime_field() -> bool;
}
