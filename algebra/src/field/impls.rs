pub mod f32 {
    use crate::reduce::*;

    #[doc = r" This define a field based the barrett reduction."]
    #[derive(Debug, Clone, Copy)]
    pub struct U32FieldEval<const P: u32>;

    impl<const P: u32> crate::Field for U32FieldEval<P> {
        type ValueT = u32;
        type Modulus = crate::modulus::BarrettModulus<u32>;
        const MODULUS_VALUE: Self::ValueT = P;
        const MODULUS: Self::Modulus = Self::Modulus::new(P);
        const ZERO: Self::ValueT = 0;
        const ONE: Self::ValueT = 1;
        const MINUS_ONE: Self::ValueT = P - 1;
        #[doc = r" Calculates `a + b`."]
        #[inline]
        fn add(a: Self::ValueT, b: Self::ValueT) -> Self::ValueT {
            Self::MODULUS_VALUE.reduce_add(a, b)
        }
        #[doc = r" Calculates `a += b`."]
        #[inline]
        fn add_assign(a: &mut Self::ValueT, b: Self::ValueT) {
            Self::MODULUS_VALUE.reduce_add_assign(a, b);
        }
        #[doc = r" Calculates `2*value`."]
        #[inline]
        fn double(value: Self::ValueT) -> Self::ValueT {
            Self::MODULUS_VALUE.reduce_double(value)
        }
        #[doc = r" Calculates `value = 2*value`."]
        #[inline]
        fn double_assign(value: &mut Self::ValueT) {
            Self::MODULUS_VALUE.reduce_double_assign(value);
        }
        #[doc = r" Calculates `a - b`."]
        #[inline]
        fn sub(a: Self::ValueT, b: Self::ValueT) -> Self::ValueT {
            Self::MODULUS_VALUE.reduce_sub(a, b)
        }
        #[doc = r" Calculates `a -= b`."]
        #[inline]
        fn sub_assign(a: &mut Self::ValueT, b: Self::ValueT) {
            Self::MODULUS_VALUE.reduce_sub_assign(a, b);
        }
        #[doc = r" Calculates `-value`."]
        #[inline]
        fn neg(value: Self::ValueT) -> Self::ValueT {
            Self::MODULUS_VALUE.reduce_neg(value)
        }
        #[doc = r" Calculates `-value`."]
        #[inline]
        fn neg_assign(value: &mut Self::ValueT) {
            Self::MODULUS_VALUE.reduce_neg_assign(value);
        }
        #[doc = r" Calculate the multiplicative inverse of `value`."]
        #[inline]
        fn inv(value: Self::ValueT) -> Self::ValueT {
            Self::MODULUS_VALUE.reduce_inv(value)
        }
        #[doc = r" Calculates `value^(-1)`."]
        #[inline]
        fn inv_assign(value: &mut Self::ValueT) {
            Self::MODULUS_VALUE.reduce_inv_assign(value);
        }
    }
    impl<const P: u32> crate::NttField for U32FieldEval<P> {
        #[cfg(not(feature = "concrete-ntt"))]
        type Table = crate::ntt::FieldTableWithShoupRoot<Self>;
        #[cfg(feature = "concrete-ntt")]
        type Table = crate::ntt::Concrete32Table<Self>;
        #[inline]
        fn generate_ntt_table(log_n: u32) -> Result<Self::Table, crate::AlgebraError> {
            crate::ntt::NttTable::new(<Self as crate::Field>::MODULUS, log_n)
        }
    }
}

pub mod f64 {
    use crate::reduce::*;

    #[doc = r" This define a field based the barrett reduction."]
    #[derive(Debug, Clone, Copy)]
    pub struct U64FieldEval<const P: u64>;

    impl<const P: u64> crate::Field for U64FieldEval<P> {
        type ValueT = u64;
        type Modulus = crate::modulus::BarrettModulus<u64>;
        const MODULUS_VALUE: Self::ValueT = P;
        const MODULUS: Self::Modulus = Self::Modulus::new(P);
        const ZERO: Self::ValueT = 0;
        const ONE: Self::ValueT = 1;
        const MINUS_ONE: Self::ValueT = P - 1;
        #[doc = r" Calculates `a + b`."]
        #[inline]
        fn add(a: Self::ValueT, b: Self::ValueT) -> Self::ValueT {
            Self::MODULUS_VALUE.reduce_add(a, b)
        }
        #[doc = r" Calculates `a += b`."]
        #[inline]
        fn add_assign(a: &mut Self::ValueT, b: Self::ValueT) {
            Self::MODULUS_VALUE.reduce_add_assign(a, b);
        }
        #[doc = r" Calculates `2*value`."]
        #[inline]
        fn double(value: Self::ValueT) -> Self::ValueT {
            Self::MODULUS_VALUE.reduce_double(value)
        }
        #[doc = r" Calculates `value = 2*value`."]
        #[inline]
        fn double_assign(value: &mut Self::ValueT) {
            Self::MODULUS_VALUE.reduce_double_assign(value);
        }
        #[doc = r" Calculates `a - b`."]
        #[inline]
        fn sub(a: Self::ValueT, b: Self::ValueT) -> Self::ValueT {
            Self::MODULUS_VALUE.reduce_sub(a, b)
        }
        #[doc = r" Calculates `a -= b`."]
        #[inline]
        fn sub_assign(a: &mut Self::ValueT, b: Self::ValueT) {
            Self::MODULUS_VALUE.reduce_sub_assign(a, b);
        }
        #[doc = r" Calculates `-value`."]
        #[inline]
        fn neg(value: Self::ValueT) -> Self::ValueT {
            Self::MODULUS_VALUE.reduce_neg(value)
        }
        #[doc = r" Calculates `-value`."]
        #[inline]
        fn neg_assign(value: &mut Self::ValueT) {
            Self::MODULUS_VALUE.reduce_neg_assign(value);
        }
        #[doc = r" Calculate the multiplicative inverse of `value`."]
        #[inline]
        fn inv(value: Self::ValueT) -> Self::ValueT {
            Self::MODULUS_VALUE.reduce_inv(value)
        }
        #[doc = r" Calculates `value^(-1)`."]
        #[inline]
        fn inv_assign(value: &mut Self::ValueT) {
            Self::MODULUS_VALUE.reduce_inv_assign(value);
        }
    }
    impl<const P: u64> crate::NttField for U64FieldEval<P> {
        #[cfg(not(feature = "concrete-ntt"))]
        type Table = crate::ntt::FieldTableWithShoupRoot<Self>;
        #[cfg(feature = "concrete-ntt")]
        type Table = crate::ntt::Concrete64Table<Self>;
        #[inline]
        fn generate_ntt_table(log_n: u32) -> Result<Self::Table, crate::AlgebraError> {
            crate::ntt::NttTable::new(<Self as crate::Field>::MODULUS, log_n)
        }
    }
}
