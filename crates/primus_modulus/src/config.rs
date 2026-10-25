//! Constant-friendly modulus descriptions and checked reducer preparation.

use primus_integer::FheUint;
use primus_reduce::Modulus;

use crate::{BarrettModulus, NativeModulus, PowOf2Modulus};

/// A constant-friendly modulus description with a statically selected reducer.
///
/// `M` retains the reduction representation: an explicit power of two uses
/// [`PowOf2Modulus`], a native torus uses [`NativeModulus`], and general explicit moduli use
/// [`BarrettModulus`]. [`TryFrom`] validates the representation and prepares
/// the reducer's ratios or masks once. This does not check primality or NTT
/// compatibility.
///
/// # Example
///
/// ```
/// use primus_modulus::{ModulusConfig, PowOf2Modulus};
///
/// const CONFIG: ModulusConfig<PowOf2Modulus<u64>> = ModulusConfig::Explicit(1 << 52);
/// let modulus = PowOf2Modulus::try_from(CONFIG)?;
/// # Ok::<(), primus_modulus::ModulusConfigError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModulusConfig<M: Modulus> {
    /// The full-width modulus `2^M::ValueT::BITS`; valid only for NativeModulus.
    Native,
    /// A representable modulus, checked against the selected reducer's range.
    Explicit(M::ValueT),
}

/// A modulus description incompatible with its selected reduction representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ModulusConfigError {
    /// Barrett requires an explicit modulus with two bits of multiplication headroom.
    #[error("Barrett requires an explicit modulus 1 < q < 2^(word_bits - 2)")]
    Barrett,
    /// An explicit power of two must be representable and greater than one.
    #[error("PowOf2 requires an explicit modulus 2^k with 1 <= k < word_bits")]
    PowOf2,
    /// The native torus is implicit; no representable explicit value equals it.
    #[error("Native requires the implicit full-width modulus")]
    Native,
}

impl<M: Modulus> From<M> for ModulusConfig<M> {
    fn from(modulus: M) -> Self {
        match modulus.explicit_value() {
            Some(value) => Self::Explicit(value),
            None => Self::Native,
        }
    }
}

impl<T: FheUint> TryFrom<ModulusConfig<BarrettModulus<T>>> for BarrettModulus<T> {
    type Error = ModulusConfigError;

    fn try_from(config: ModulusConfig<Self>) -> Result<Self, Self::Error> {
        match config {
            ModulusConfig::Explicit(value) => {
                Self::try_new(value).ok_or(ModulusConfigError::Barrett)
            }
            ModulusConfig::Native => Err(ModulusConfigError::Barrett),
        }
    }
}

impl<T: FheUint> TryFrom<ModulusConfig<PowOf2Modulus<T>>> for PowOf2Modulus<T> {
    type Error = ModulusConfigError;

    fn try_from(config: ModulusConfig<Self>) -> Result<Self, Self::Error> {
        match config {
            ModulusConfig::Explicit(value) if value > T::ONE && value.is_power_of_two() => {
                Ok(Self::new(value))
            }
            _ => Err(ModulusConfigError::PowOf2),
        }
    }
}

impl<T: FheUint> TryFrom<ModulusConfig<NativeModulus<T>>> for NativeModulus<T> {
    type Error = ModulusConfigError;

    fn try_from(config: ModulusConfig<Self>) -> Result<Self, Self::Error> {
        match config {
            ModulusConfig::Native => Ok(Self::new()),
            ModulusConfig::Explicit(_) => Err(ModulusConfigError::Native),
        }
    }
}
