use algebra::integer::UnsignedInteger;
use num_traits::ConstOne;

/// Represents different types of modulus values.
///
/// # Type Parameters
///
/// * `C` - An unsigned integer type that represents the coefficients.
#[derive(Debug, Clone, Copy)]
pub enum ModulusValue<C: UnsignedInteger> {
    /// Native modulus.
    Native,
    /// Power of 2 modulus.
    PowerOf2(C),
    /// Prime modulus.
    Prime(C),
    /// Other types of modulus.
    Others(C),
}

impl<C: UnsignedInteger> ModulusValue<C> {
    /// Returns modulus minus one.
    #[inline]
    pub fn modulus_minus_one(self) -> C {
        match self {
            ModulusValue::Native => C::MAX,
            ModulusValue::PowerOf2(value)
            | ModulusValue::Prime(value)
            | ModulusValue::Others(value) => value - <C as ConstOne>::ONE,
        }
    }

    /// Returns log modulus, also known as modulus bits.
    #[inline]
    pub fn log_modulus(self) -> u32 {
        match self {
            ModulusValue::Native => C::BITS,
            ModulusValue::PowerOf2(q) => q.trailing_zeros(),
            ModulusValue::Prime(q) | ModulusValue::Others(q) => C::BITS - q.leading_zeros(),
        }
    }

    /// Returns `true` if the modulus value is [`Native`].
    ///
    /// [`Native`]: ModulusValue::Native
    #[must_use]
    #[inline]
    pub fn is_native(&self) -> bool {
        matches!(self, Self::Native)
    }

    /// Returns `true` if the modulus value is [`PowerOf2`].
    ///
    /// [`PowerOf2`]: ModulusValue::PowerOf2
    #[must_use]
    #[inline]
    pub fn is_power_of2(&self) -> bool {
        matches!(self, Self::PowerOf2(..))
    }

    /// Returns an `Option` containing a reference to the value
    /// if the modulus value is [`PowerOf2`].
    ///
    /// [`PowerOf2`]: ModulusValue::PowerOf2
    #[inline]
    pub fn as_power_of2(&self) -> Option<&C> {
        if let Self::PowerOf2(v) = self {
            Some(v)
        } else {
            None
        }
    }
}
