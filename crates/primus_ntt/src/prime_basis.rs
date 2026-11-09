use primus_modulus::is_prime_u64;
use primus_shape::PolyLength;

use crate::U64_NTT_MAX_MODULUS_BITS;

/// Invalid ordered basis for the optimized u64 negacyclic NTT.
#[derive(Debug, thiserror::Error)]
pub enum U64NttPrimeBasisError {
    /// The basis has no moduli.
    #[error("an NTT prime basis must be nonempty")]
    EmptyBasis,
    /// The modulus exceeds the lazy reduction range.
    #[error("NTT modulus {modulus} must be below 2^62")]
    ModulusTooLarge {
        /// Rejected modulus.
        modulus: u64,
    },
    /// Each modulus may occur only once.
    #[error("NTT modulus {modulus} occurs more than once")]
    DuplicatePrime {
        /// Repeated modulus.
        modulus: u64,
    },
    /// The modulus is composite or less than two.
    #[error("NTT modulus {modulus} is not prime")]
    NotPrime {
        /// Rejected modulus.
        modulus: u64,
    },
    /// The prime does not support the required root order.
    #[error("NTT modulus {modulus} is not congruent to 1 modulo {order}")]
    NttOrder {
        /// Rejected prime.
        modulus: u64,
        /// Required root order, 2N.
        order: u64,
    },
}

/// Checks the complete ordered basis before preparing a native u64 NTT domain.
///
/// Uses deterministic primality testing. Successful table construction alone
/// does not establish that a supplied modulus is prime.
///
/// # Errors
/// Rejects an empty basis, duplicate or composite moduli, moduli outside the
/// optimized u64 range, or primes without the required negacyclic root order.
pub fn validate_u64_ntt_primes(
    length: PolyLength,
    primes: &[u64],
) -> Result<(), U64NttPrimeBasisError> {
    use U64NttPrimeBasisError as Error;

    if primes.is_empty() {
        return Err(Error::EmptyBasis);
    }
    let order = 2 * length.get() as u64;
    for (index, &modulus) in primes.iter().enumerate() {
        if modulus >= 1u64 << U64_NTT_MAX_MODULUS_BITS {
            return Err(Error::ModulusTooLarge { modulus });
        }
        if primes[..index].contains(&modulus) {
            return Err(Error::DuplicatePrime { modulus });
        }
        if !is_prime_u64(modulus) {
            return Err(Error::NotPrime { modulus });
        }
        if !(modulus - 1).is_multiple_of(order) {
            return Err(Error::NttOrder { modulus, order });
        }
    }
    Ok(())
}
