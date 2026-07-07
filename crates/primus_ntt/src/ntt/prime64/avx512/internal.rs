/// Maximum power of 2 in degree
pub(crate) const MAX_DEGREE_BITS: u32 = 20;

/// Maximum number of bits in modulus
pub(crate) const MAX_MODULUS_BITS: u32 = 62;

/// Default bit shift used in Barrett precomputation
pub(crate) const DEFAULT_SHIFT_BITS: u32 = 64;

/// Bit shift used in Barrett precomputation when AVX512-IFMA
/// acceleration is enabled
pub(crate) const IFMA_SHIFT_BITS: u32 = 52;

/// Maximum modulus to use 32-bit AVX512-DQ acceleration for the
/// forward transform
pub(crate) const MAX_FWD_32_MODULUS: u64 = 1u64 << (32 - 2);

/// Maximum modulus to use 32-bit AVX512-DQ acceleration for the
/// inverse transform
pub(crate) const MAX_INV_32_MODULUS: u64 = 1u64 << (32 - 1);

/// Maximum modulus to use AVX512-IFMA acceleration for the forward
/// transform
pub(crate) const MAX_FWD_IFMA_MODULUS: u64 = 1u64 << (IFMA_SHIFT_BITS - 2);

/// Maximum modulus to use AVX512-IFMA acceleration for the inverse
/// transform
pub(crate) const MAX_INV_IFMA_MODULUS: u64 = 1u64 << (IFMA_SHIFT_BITS - 2);

/// Maximum modulus to use AVX512-DQ acceleration for the inverse
/// transform
pub(crate) const MAX_INV_DQ_MODULUS: u64 = 1u64 << (DEFAULT_SHIFT_BITS - 1);

pub(crate) fn max_fwd_modulus(bit_shift: u32) -> u64 {
    if bit_shift == 32 {
        MAX_FWD_32_MODULUS
    } else if bit_shift == 52 {
        MAX_FWD_IFMA_MODULUS
    } else if bit_shift == 64 {
        1u64 << MAX_MODULUS_BITS
    } else {
        debug_assert!(false, "Invalid bit_shift {}", bit_shift);
        0
    }
}

pub(crate) fn max_inv_modulus(bit_shift: u32) -> u64 {
    if bit_shift == 32 {
        MAX_INV_32_MODULUS
    } else if bit_shift == 52 {
        MAX_INV_IFMA_MODULUS
    } else if bit_shift == 64 {
        MAX_INV_DQ_MODULUS
    } else {
        debug_assert!(false, "Invalid bit_shift {}", bit_shift);
        0
    }
}

pub fn check_arguments(n: usize, modulus: u64) {
    debug_assert!(n.is_power_of_two(), "n {n} is not a power of 2");
    debug_assert!(
        n <= (1usize << MAX_DEGREE_BITS),
        "n should be less than 2^{MAX_DEGREE_BITS} got {n}"
    );
    debug_assert!(
        modulus < (1u64 << MAX_MODULUS_BITS),
        "modulus should be less than 2^{MAX_MODULUS_BITS} got {modulus}",
    );
    debug_assert!(modulus % (2 * n as u64) == 1, "modulus mod 2n != 1",);
    // FIXME: verifying primality at table construction time would catch
    // invalid moduli early, but is currently deferred to the caller.
}
