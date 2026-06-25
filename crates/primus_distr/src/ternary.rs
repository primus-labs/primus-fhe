use primus_integer::Integer;
use rand::{Rng, distr::Distribution};

/// The ternary sampler.
///
/// prob\[1] = prob\[-1] = 0.25
///
/// prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct SparseTernaryDistr<T: Integer> {
    minus_one: T,
}

impl<T: Integer> SparseTernaryDistr<T> {
    /// Creates a new [`SparseTernaryDistr`].
    #[inline]
    pub fn new(minus_one: T) -> Self {
        Self { minus_one }
    }
}

impl<T: Integer> Distribution<T> for SparseTernaryDistr<T> {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> T {
        [T::ZERO, T::ZERO, T::ONE, self.minus_one][(rng.next_u32() & 0b11) as usize]
    }
}
