use algebra::{modulus::PowOf2Modulus, reduce::Reduce};

/// LWE Plain text
pub type LWEPlaintext = bool;

/// LWE ciphertext inner value type
pub type LWEType = u16;

/// Performs dot product for two slices
#[inline]
pub fn dot_product(u: &[LWEType], v: &[LWEType], modulus: PowOf2Modulus<LWEType>) -> LWEType {
    debug_assert_eq!(u.len(), v.len());
    u.iter()
        .zip(v)
        .fold(LWEType::default(), |acc, (&x, &y)| {
            acc.wrapping_add(x.wrapping_mul(y))
        })
        .reduce(modulus)
}
