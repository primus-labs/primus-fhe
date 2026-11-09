use num_traits::Zero;

/// Whether to prefer division through a double-width integer over two
/// half-word divisions. This compile-time choice reflects how efficiently the
/// compiler lowers double-width division on the target architecture.
///
/// Types no wider than 16 bits always use double-width division because their
/// corresponding u16 or u32 operation is native on every supported target.
const PREFER_WIDE_DIVISION: bool = cfg!(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "aarch64"
));

/// Combined division and remainder for unsigned integers.
pub trait DivRem: Sized {
    /// Computes `(self / divisor, self % divisor)` in one operation.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn div_rem(self, divisor: Self) -> (Self, Self);
}

macro_rules! impl_div_rem {
    ($($T:ty)*) => {$(
        impl DivRem for $T {
            #[inline]
            fn div_rem(self, rhs: Self) -> (Self, Self) {
                (self / rhs, self % rhs)
            }
        })*
    };
}

impl_div_rem! { u8 u16 u32 u64 u128 usize }

/// Multi-limb division by a single-limb scalar.
pub trait DivRemScalar: Sized {
    /// Divides a multi-limb `dividend` by a single-limb `divisor`, writing the
    /// quotient into `quotient` and returning the remainder.
    ///
    /// Limbs are stored in least-significant-first order. The quotient has the
    /// same number of limbs as the dividend and is fully overwritten, including
    /// any leading zero limbs. The returned remainder is less than `divisor`.
    ///
    /// Callers must provide a non-empty dividend and an equally sized quotient
    /// buffer. Implementations verify these internal contracts in debug builds.
    ///
    /// # Panics
    ///
    /// Panics if `divisor` is zero.
    fn div_rem_scalar(dividend: &[Self], divisor: Self, quotient: &mut [Self]) -> Self;
}

/// Division of a double-width dividend by a single-limb divisor.
///
/// Callers must ensure `hi < divisor`, which guarantees that the quotient fits
/// in one limb. Implementations verify this internal contract in debug builds.
pub trait DivWide: Sized {
    /// Computes `((hi << BITS) | lo) / divisor`.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn div_wide(lo: Self, hi: Self, divisor: Self) -> Self;
}

macro_rules! impl_div_wide {
    ($T:ty, $W:ty) => {
        impl DivWide for $T {
            #[inline]
            fn div_wide(lo: Self, hi: Self, divisor: Self) -> Self {
                debug_assert!(hi < divisor);
                let dividend = (lo as $W) | ((hi as $W) << <$T>::BITS);
                (dividend / divisor as $W) as $T
            }
        }
    };
}

impl_div_wide!(u8, u16);
impl_div_wide!(u16, u32);
impl_div_wide!(u32, u64);
impl_div_wide!(u64, u128);

#[cfg(target_pointer_width = "64")]
impl_div_wide!(usize, u128);

#[cfg(target_pointer_width = "32")]
impl_div_wide!(usize, u64);

/// Multi-limb division by a scalar for types that fit in a wider word.
///
/// The helper functions and constants are kept inside the method body so they do
/// not pollute the module namespace.
macro_rules! impl_div_rem_scalar {
    ($T:ty, $W:ty) => {
        impl DivRemScalar for $T {
            fn div_rem_scalar(dividend: &[Self], divisor: Self, quotient: &mut [Self]) -> $T {
                const HALF_BITS: u32 = <$T>::BITS >> 1;
                const LO_MASK: $T = (<$T>::MAX) >> HALF_BITS;

                debug_assert!(!dividend.is_empty());
                debug_assert_eq!(dividend.len(), quotient.len());

                if divisor.is_zero() {
                    panic!("attempt to divide by zero")
                }

                if divisor == 1 {
                    quotient.copy_from_slice(dividend);
                    return 0;
                }

                // Only the lowest limb is non-zero — use native division directly.
                if dividend[1..].iter().all(|&v| v.is_zero()) {
                    quotient.fill(0);
                    let (q, r) = dividend[0].div_rem(divisor);
                    quotient[0] = q;
                    return r;
                }

                // Strip trailing zero limbs so the per-limb loop processes fewer
                // iterations.
                let mut dividend = dividend;
                let mut quotient = quotient;
                if dividend.last().is_some_and(|v| v.is_zero()) {
                    let last_non_zero = dividend.iter().rposition(|&v| !v.is_zero()).unwrap();
                    quotient[last_non_zero + 1..].fill(0);
                    dividend = &dividend[..=last_non_zero];
                    quotient = &mut quotient[..=last_non_zero];
                }

                let mut rem = 0;

                // u8 / u16 always use div_wide: their cast target types
                // (u16 / u32) are native division on every supported target.
                if <$T>::BITS > 16 && !PREFER_WIDE_DIVISION && divisor <= LO_MASK {
                    /// Divide `(rem << BITS) | digit` by `divisor`, returning
                    /// `(quotient, remainder)`.
                    ///
                    /// This splits the dividend into two half-width pieces and
                    /// performs two native divisions, avoiding the need for a
                    /// wider type.
                    #[inline]
                    fn div_half(rem: $T, digit: $T, divisor: $T) -> ($T, $T) {
                        const HALF: u32 = <$T>::BITS >> 1;
                        const MASK: $T = (<$T>::MAX) >> HALF;
                        debug_assert!(rem < divisor && divisor <= MASK);
                        let (hi, rem) = ((rem << HALF) | (digit >> HALF)).div_rem(divisor);
                        let (lo, rem) = ((rem << HALF) | (digit & MASK)).div_rem(divisor);
                        ((hi << HALF) | lo, rem)
                    }

                    for (&d_elem, q_elem) in dividend.iter().rev().zip(quotient.iter_mut().rev()) {
                        let (q, r) = div_half(rem, d_elem, divisor);
                        *q_elem = q;
                        rem = r;
                    }
                } else {
                    /// Divide `(hi << BITS) | lo` by `divisor`, returning
                    /// `(quotient, remainder)` using a wider integer type.
                    #[inline]
                    fn div_wide(hi: $T, lo: $T, divisor: $T) -> ($T, $T) {
                        debug_assert!(hi < divisor);
                        let lhs = lo as $W | ((hi as $W) << <$T>::BITS);
                        let rhs = divisor as $W;
                        ((lhs / rhs) as $T, (lhs % rhs) as $T)
                    }

                    for (&d_elem, q_elem) in dividend.iter().rev().zip(quotient.iter_mut().rev()) {
                        let (q, r) = div_wide(rem, d_elem, divisor);
                        *q_elem = q;
                        rem = r;
                    }
                }

                rem
            }
        }
    };
}

impl_div_rem_scalar!(u8, u16);
impl_div_rem_scalar!(u16, u32);
impl_div_rem_scalar!(u32, u64);
impl_div_rem_scalar!(u64, u128);

#[cfg(target_pointer_width = "64")]
impl_div_rem_scalar!(usize, u128);

#[cfg(target_pointer_width = "32")]
impl_div_rem_scalar!(usize, u64);

mod u128_division;
