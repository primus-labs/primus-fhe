use primus_integer::{FheUint, SignedInteger};

mod cdt;
mod parameters;
#[cfg(feature = "high_precision")]
mod precise_cdt;
mod ziggurat;

pub(crate) use cdt::build_cdt;
#[cfg(feature = "high_precision")]
pub(crate) use parameters::PRECISE_CDT_MAX_MAGNITUDE;
pub(crate) use parameters::{CDT_MAX_MAGNITUDE, DEFAULT_TAIL_CUT, GaussianParameters};
#[cfg(feature = "high_precision")]
pub(crate) use precise_cdt::{build_precise_cdt, compare_u256};
pub(crate) use ziggurat::ZigguratMagnitudeSampler;

/// Encodes a sampled magnitude in the canonical unsigned modulus range.
#[inline(always)]
pub(crate) fn encode_modular<T: FheUint>(positive: bool, magnitude: T, modulus_minus_one: T) -> T {
    if magnitude.is_zero() {
        T::ZERO
    } else if positive {
        magnitude
    } else {
        modulus_minus_one - magnitude + T::ONE
    }
}

/// Applies the sampled sign to a non-negative magnitude.
#[inline(always)]
pub(crate) fn encode_signed<T: SignedInteger>(positive: bool, magnitude: T) -> T {
    if positive { magnitude } else { -magnitude }
}

/// Fills a batch from one already selected Gaussian backend.
#[inline]
pub(crate) fn sample_to<T, D: rand::distr::Distribution<T>, R: rand::Rng + ?Sized>(
    output: &mut [T],
    distr: &D,
    rng: &mut R,
) {
    for out in output {
        *out = distr.sample(rng);
    }
}
