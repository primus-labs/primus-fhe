use primus_integer::{FheInt, Integer};
use rand::{
    Rng,
    distr::{Bernoulli, Distribution},
};

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

pub(crate) fn fill_binary<T: FheInt, R: Rng + rand::CryptoRng>(
    output: &mut [T],
    distribution: &Bernoulli,
    rng: &mut R,
) {
    for (out, sample) in output.iter_mut().zip(distribution.sample_iter(rng)) {
        *out = if sample { T::ONE } else { T::ZERO };
    }
}
