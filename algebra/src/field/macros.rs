macro_rules! impl_barrett_field {
    ($(#[$cfg:meta])* impl $Vis:vis $FieldName:ident<$ValueT:ty>) => {
        /// This define a field based the barrett reduction.
        $(#[$cfg])*
        $Vis struct $FieldName<const P:$ValueT>;

        impl<const P:$ValueT> $crate::Field for $FieldName<P> {
            type ValueT = $ValueT;
            type Modulus = $crate::modulus::BarrettModulus<$ValueT>;

            const MODULUS_VALUE: Self::ValueT = P;
            const MODULUS: Self::Modulus = Self::Modulus::new(P);
            const ZERO: Self::ValueT = 0;
            const ONE: Self::ValueT = 1;
            const MINUS_ONE: Self::ValueT = P - 1;

            /// Calculates `a + b`.
            #[inline]
            fn add(a: Self::ValueT, b: Self::ValueT) -> Self::ValueT {
                Self::MODULUS_VALUE.reduce_add(a, b)
            }

            /// Calculates `a += b`.
            #[inline]
            fn add_assign(a: &mut Self::ValueT, b: Self::ValueT) {
                Self::MODULUS_VALUE.reduce_add_assign(a, b);
            }

            /// Calculates `2*value`.
            #[inline]
            fn double(value: Self::ValueT) -> Self::ValueT {
                Self::MODULUS_VALUE.reduce_double(value)
            }

            /// Calculates `value = 2*value`.
            #[inline]
            fn double_assign(value: &mut Self::ValueT) {
                Self::MODULUS_VALUE.reduce_double_assign(value);
            }

            /// Calculates `a - b`.
            #[inline]
            fn sub(a: Self::ValueT, b: Self::ValueT) -> Self::ValueT {
                Self::MODULUS_VALUE.reduce_sub(a, b)
            }

            /// Calculates `a -= b`.
            #[inline]
            fn sub_assign(a: &mut Self::ValueT, b: Self::ValueT) {
                Self::MODULUS_VALUE.reduce_sub_assign(a, b);
            }

            /// Calculates `-value`.
            #[inline]
            fn neg(value: Self::ValueT) -> Self::ValueT {
                Self::MODULUS_VALUE.reduce_neg(value)
            }

            /// Calculates `-value`.
            #[inline]
            fn neg_assign(value: &mut Self::ValueT) {
                Self::MODULUS_VALUE.reduce_neg_assign(value);
            }

            /// Calculate the multiplicative inverse of `value`.
            #[inline]
            fn inv(value: Self::ValueT) -> Self::ValueT {
                Self::MODULUS_VALUE.reduce_inv(value)
            }

            /// Calculates `value^(-1)`.
            #[inline]
            fn inv_assign(value: &mut Self::ValueT) {
                Self::MODULUS_VALUE.reduce_inv_assign(value);
            }
        }

        impl<const P:$ValueT> $crate::NttField for $FieldName<P> {
            type Table = $crate::ntt::FieldTableWithShoupRoot<Self>;

            #[inline]
            fn generate_ntt_table(log_n: u32) -> Result<Self::Table, $crate::AlgebraError> {
                $crate::ntt::NttTable::new(<Self as $crate::Field>::MODULUS, log_n)
            }
        }
    };
}
