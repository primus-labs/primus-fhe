const FAST_DIV_WIDE: bool = cfg!(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "aarch64"
));

macro_rules! impl_gen_ratio {
    ($T:ty, $W:ty, $HALF_BITS:ident, $LO_MASK:ident, $gen_ratio:ident, $div_rem:ident, $div_half:ident, $div_wide:ident) => {
        const $HALF_BITS: u32 = <$T>::BITS >> 1;
        const $LO_MASK: $T = <$T>::MAX >> $HALF_BITS;

        #[inline]
        const fn $div_rem(numerator: $T, divisor: $T) -> ($T, $T) {
            (numerator / divisor, numerator % divisor)
        }

        #[inline]
        const fn $div_half(rem: $T, divisor: $T) -> ($T, $T) {
            let (hi, rem) = $div_rem(rem << $HALF_BITS, divisor);
            let (lo, rem) = $div_rem(rem << $HALF_BITS, divisor);
            ((hi << $HALF_BITS) | lo, rem)
        }

        #[inline]
        const fn $div_wide(hi: $T, divisor: $T) -> ($T, $T) {
            let lhs = (hi as $W) << <$T>::BITS;
            let rhs = divisor as $W;
            ((lhs / rhs) as $T, (lhs % rhs) as $T)
        }

        #[inline]
        pub(crate) const fn $gen_ratio(value: $T) -> [$T; 2] {
            let mut numerator = [0, 0];

            if !FAST_DIV_WIDE && value <= $LO_MASK {
                let (q, r) = $div_half(1, value);
                numerator[1] = q;

                let (q, _) = $div_half(r, value);
                numerator[0] = q;
            } else {
                let (q, r) = $div_wide(1, value);
                numerator[1] = q;

                let (q, _) = $div_wide(r, value);
                numerator[0] = q;
            }
            numerator
        }
    };
}

impl_gen_ratio!(
    u16,
    u32,
    HALF_BITS_U16,
    LO_MASK_U16,
    gen_ratio_u16,
    div_rem_u16,
    div_half_u16,
    div_wide_u16
);

impl_gen_ratio!(
    u32,
    u64,
    HALF_BITS_U32,
    LO_MASK_U32,
    gen_ratio_u32,
    div_rem_u32,
    div_half_u32,
    div_wide_u32
);

impl_gen_ratio!(
    u64,
    u128,
    HALF_BITS_U64,
    LO_MASK_U64,
    gen_ratio_u64,
    div_rem_u64,
    div_half_u64,
    div_wide_u64
);
