#[macro_use]
mod internal_macros;

mod ops;

/// A prime modulus, using barrett reduction algorithm.
///
/// The struct stores the modulus number and some precomputed
/// data. Here, `b` = 2^T::BITS
///
/// It's efficient if many reductions are performed with a single modulus.
#[derive(Clone)]
pub struct PrimeModulus<T> {
    /// the value to indicate the modulus
    value: T,
    /// ratio `µ` = ⌊b^2/value⌋
    ratio: [T; 2],
    /// the bit count of the value
    bit_count: u32,
}

impl<T: Copy> PrimeModulus<T> {
    /// Returns the value of this [`PrimeModulus<T>`].
    #[inline]
    pub fn value(&self) -> T {
        self.value
    }

    /// Returns the ratio of this [`PrimeModulus<T>`].
    #[inline]
    pub fn ratio(&self) -> [T; 2] {
        self.ratio
    }
}

impl<T> PrimeModulus<T> {
    /// Returns the bit count of this [`PrimeModulus<T>`].
    #[inline]
    pub fn bit_count(&self) -> u32 {
        self.bit_count
    }
}

impl_prime_modulus!(impl PrimeModulus<u8>; WideType: u16);
impl_prime_modulus!(impl PrimeModulus<u16>; WideType: u32);
impl_prime_modulus!(impl PrimeModulus<u32>; WideType: u64);
impl_prime_modulus!(impl PrimeModulus<u64>; WideType: u128);
