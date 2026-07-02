/// Returns the maximum value representable with `bits` bits.
///
/// - `bits` must be <= 64.
/// - If `bits == 64`, returns `u64::MAX`.
#[inline]
pub fn maximum_value(bits: u32) -> u64 {
    debug_assert!(bits <= 64, "maximum_value requires bits <= 64; got {bits}");
    if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// Returns `x mod modulus`, assuming `x < 2 * modulus`.
#[inline]
pub fn reduce_once(mut x: u64, modulus: u64) -> u64 {
    if x >= modulus {
        x -= modulus;
    }
    x
}

/// Returns `x mod modulus`, assuming `x < 4 * modulus`.
/// `twice_modulus` must equal `2 * modulus`.
#[inline]
pub fn reduce_twice(mut x: u64, modulus: u64, twice_modulus: u64) -> u64 {
    debug_assert_eq!(twice_modulus, 2 * modulus);

    if x >= twice_modulus {
        x -= twice_modulus;
    }
    if x >= modulus {
        x -= modulus;
    }
    x
}

/// Computes `(x * y) mod modulus`, except the output is in `[0, 2 * modulus]`.
///
/// `y_operand` must be < `modulus`.
/// `x` and `modulus` must be <= `maximum_value(BIT_SHIFT)`.
///
/// `y_barrett_factor` is the precomputed Barrett factor:
/// `floor((y_operand << BIT_SHIFT) / modulus)`.
#[inline]
pub fn multiply_mod_lazy<const BIT_SHIFT: u32>(
    x: u64,
    y_operand: u64,
    y_barrett_factor: u64,
    modulus: u64,
) -> u64 {
    debug_assert!(
        y_operand < modulus,
        "y_operand {y_operand} must be less than modulus {modulus}"
    );

    let max = maximum_value(BIT_SHIFT);
    debug_assert!(modulus <= max, "modulus {modulus} exceeds bound {max}");
    debug_assert!(x <= max, "operand {x} exceeds bound {max}");

    let q = multiply_u64_hi::<BIT_SHIFT>(x, y_barrett_factor);

    y_operand
        .wrapping_mul(x)
        .wrapping_sub(q.wrapping_mul(modulus))
}

/// Return the high (128 - BIT_SHIFT) bits of the 128-bit product `x * y`,
/// i.e. `(x * y) >> BIT_SHIFT`.
#[inline]
pub fn multiply_u64_hi<const BIT_SHIFT: u32>(x: u64, y: u64) -> u64 {
    let product: u128 = (x as u128) * (y as u128);
    (product >> BIT_SHIFT) as u64
}
