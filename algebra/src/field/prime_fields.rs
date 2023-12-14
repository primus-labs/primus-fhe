//! This place defines some concrete implement of the prime field.

use super::Field;

/// A trait specifying a `Field` that is also a prime field.
///
/// A prime field is a special type of field with a characteristic that is a prime number.
/// This trait ensures that the implementing type adheres to the mathematical properties
/// of a prime field. Prime fields are widely used in cryptography due to their simplicity
/// and the security properties they offer, such as a high degree of randomness and uniformity
/// in the distribution of elements.
///
/// Types implementing `PrimeField` must be capable of determining whether they indeed represent
/// a prime field, typically by checking if their modulus is a prime number, which is a fundamental
/// requirement for a field to be a prime field.
///
/// This trait is important for cryptographic algorithms that require a prime field, such as those
/// found in elliptic curve cryptography and various other cryptographic schemes where the security
/// assumptions are based on the difficulty of solving problems within a prime field.
pub trait PrimeField: Field {
    /// Check [`Self`] is a prime field.
    fn is_prime_field() -> bool;
}

/// A factor for multiply many times
#[derive(Clone, Copy, Default)]
pub struct MulFactor<F> {
    value: F,
    quotient: F,
}

impl<F: Copy> MulFactor<F> {
    /// Creates a new instance.
    #[inline]
    pub const fn new(value: F, quotient: F) -> Self {
        Self { value, quotient }
    }

    /// Returns the value of this [`MulFactor<F>`].
    #[inline]
    pub const fn value(&self) -> F {
        self.value
    }

    /// Returns the quotient of this [`MulFactor<F>`].
    #[inline]
    pub const fn quotient(&self) -> F {
        self.quotient
    }
}
