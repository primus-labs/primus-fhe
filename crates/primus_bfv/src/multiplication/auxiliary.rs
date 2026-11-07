//! Preparation shared by the exact and HPS computation-only bases.

use core::cmp::Ordering;

use primus_modulus::{BarrettModulus, is_prime_u64};
use primus_rns::RNSBase;

use crate::BfvContext;

use super::{
    BfvMultiplyError,
    words::{cmp_words, mul_scalar_to},
};

// Choose distinct 60-bit NTT primes until their exact product exceeds the
// backend's threshold. This selects arithmetic resources, not encryption or
// security parameters.
pub(super) fn search_auxiliary_moduli(
    n: usize,
    q_values: &[u64],
    exclusive_minimum: &[u64],
) -> Result<Vec<u64>, BfvMultiplyError> {
    let step = u64::try_from(n)
        .ok()
        .and_then(|n| n.checked_mul(2))
        .filter(|&step| step < (1 << 60))
        .ok_or(BfvMultiplyError::LengthOverflow)?;
    let mut product = vec![1];
    let mut primes = Vec::new();
    let mut candidate = ((1u64 << 60) - 2) / step * step + 1;
    while cmp_words(&product, exclusive_minimum) != Ordering::Greater {
        while candidate > (1 << 59)
            && (!is_prime_u64(candidate) || q_values.iter().any(|&q| gcd(candidate, q) != 1))
        {
            candidate = candidate.saturating_sub(step);
        }
        if candidate <= (1 << 59) {
            return Err(BfvMultiplyError::AuxiliarySearchExhausted);
        }
        primes.push(candidate);
        let mut next = vec![0; product.len() + 1];
        mul_scalar_to(&product, candidate, &mut next);
        product = next;
        candidate = candidate.saturating_sub(step);
    }
    Ok(primes)
}

pub(super) fn check_level(context: &BfvContext, level: usize) -> Result<(), BfvMultiplyError> {
    if level >= context.level_count() {
        return Err(BfvMultiplyError::Level {
            requested: level,
            maximum: context.level_count(),
        });
    }
    Ok(())
}

pub(super) fn prepare_auxiliary_base(
    n: usize,
    base_q: &RNSBase<u64, BarrettModulus<u64>>,
    auxiliary_moduli: &[u64],
) -> Result<RNSBase<u64, BarrettModulus<u64>>, BfvMultiplyError> {
    let two_n = n.checked_mul(2).ok_or(BfvMultiplyError::LengthOverflow)?;
    for (index, &p) in auxiliary_moduli.iter().enumerate() {
        if !(3..(1 << 62)).contains(&p) || p % two_n as u64 != 1 {
            return Err(BfvMultiplyError::AuxiliaryModulus { index, modulus: p });
        }
        for &q in base_q.moduli_values() {
            if gcd(p, q) != 1 {
                return Err(BfvMultiplyError::NonCoprime {
                    auxiliary: p,
                    ciphertext: q,
                });
            }
        }
    }
    let moduli = auxiliary_moduli
        .iter()
        .copied()
        .map(BarrettModulus::new)
        .collect();
    Ok(RNSBase::from_owned_moduli(moduli)?)
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}
