/// Extension trait to provide access to bits of integers.
pub trait Bits {
    /// The number of bits this type has.
    const BITS: u32;
}

macro_rules! bits {
    ($($T:ty),*) => {
        $(
            impl Bits for $T {
                const BITS: u32 = <$T>::BITS;
            }
        )*
    };
}

bits!(i8, u8, i16, u16, i32, u32, i64, u64, i128, u128, isize, usize);
