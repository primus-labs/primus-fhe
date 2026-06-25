use primus_integer::Integer;
use rand::{Rng, distr::Distribution};

/// The binary sampler.
///
/// prob\[1] = prob\[0] = 0.5
#[derive(Clone, Copy, Debug)]
pub struct BinaryDistr;

impl<T: Integer> Distribution<T> for BinaryDistr {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> T {
        T::as_from(rng.next_u32() & 0b1)
    }
}
