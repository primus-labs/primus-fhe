/// ntt for 32bits
pub mod prime32 {

    use concrete_ntt::prime32::Plan;

    use crate::{
        modulus::BarrettModulus,
        ntt::{NttTable, NumberTheoryTransform},
        polynomial::{FieldNttPolynomial, FieldPolynomial},
        reduce::LazyReduceMulAssign,
        utils::Pool,
        AlgebraError, Field, NttField,
    };

    /// Wrapping concrete NTT for 32bit primes.
    pub struct Concrete32Table<F>
    where
        F: Field<ValueT = u32, Modulus = BarrettModulus<u32>> + NttField<Table = Self>,
    {
        plan: Plan,
        pool: Pool<Vec<u32>>,
        modulus: <F as Field>::Modulus,
        root: <F as Field>::ValueT,
    }

    impl<F> Concrete32Table<F>
    where
        F: Field<ValueT = u32, Modulus = BarrettModulus<u32>> + NttField<Table = Self>,
    {
        /// Create a new NTT table for 32bit prime.
        #[inline]
        pub fn new(modulus: <F as Field>::Modulus, log_n: u32) -> Result<Self, AlgebraError> {
            let plan =
                Plan::try_new(1 << log_n, F::MODULUS_VALUE).ok_or(AlgebraError::NttTableErr)?;
            let root = plan.root();
            let pool = Pool::new_with(2, || vec![0; 1 << log_n]);
            Ok(Self {
                plan,
                pool,
                modulus,
                root,
            })
        }

        /// Get the root of unity.
        #[inline]
        pub fn root(&self) -> <F as Field>::ValueT {
            self.root
        }
    }

    impl<F> NttTable for Concrete32Table<F>
    where
        F: Field<ValueT = u32, Modulus = BarrettModulus<u32>> + NttField<Table = Self>,
    {
        type ValueT = u32;

        type ModulusT = <F as Field>::Modulus;

        #[inline]
        fn new(modulus: Self::ModulusT, log_n: u32) -> Result<Self, AlgebraError> {
            Concrete32Table::new(modulus, log_n)
        }

        #[inline]
        fn dimension(&self) -> usize {
            self.plan.ntt_size()
        }
    }

    impl<F> NumberTheoryTransform for Concrete32Table<F>
    where
        F: Field<ValueT = u32, Modulus = BarrettModulus<u32>> + NttField<Table = Self>,
    {
        type CoeffPoly = FieldPolynomial<F>;

        type NttPoly = FieldNttPolynomial<F>;

        #[inline]
        fn transform_inplace(&self, mut poly: Self::CoeffPoly) -> Self::NttPoly {
            self.transform_slice(poly.as_mut_slice());
            FieldNttPolynomial::new(poly.inner_data())
        }

        #[inline]
        fn inverse_transform_inplace(&self, mut values: Self::NttPoly) -> Self::CoeffPoly {
            self.inverse_transform_slice(values.as_mut_slice());
            FieldPolynomial::new(values.inner_data())
        }

        #[inline]
        fn lazy_transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]) {
            self.plan.fwd(poly);
        }

        #[inline]
        fn transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]) {
            self.plan.fwd(poly);
        }

        #[inline]
        fn lazy_inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]) {
            self.plan.inv(values);
            self.plan.normalize(values);
        }

        #[inline]
        fn inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]) {
            self.plan.inv(values);
            self.plan.normalize(values);
        }

        #[inline]
        fn transform_monomial(
            &self,
            coeff: Self::ValueT,
            degree: usize,
            values: &mut [<Self as NttTable>::ValueT],
        ) {
            self.plan.fwd_monomial(coeff, degree, values);
        }

        #[inline]
        fn transform_coeff_one_monomial(
            &self,
            degree: usize,
            values: &mut [<Self as NttTable>::ValueT],
        ) {
            self.plan.fwd_coeff_one_monomial(degree, values);
        }

        #[inline]
        fn transform_coeff_minus_one_monomial(
            &self,
            degree: usize,
            values: &mut [<Self as NttTable>::ValueT],
        ) {
            self.plan.fwd_coeff_minus_one_monomial(degree, values);
        }

        #[inline]
        fn lazy_mul_assign(&self, a: &mut Self::CoeffPoly, b: &Self::CoeffPoly) {
            let mut bv = self.pool.try_get().map_or_else(
                || b.as_slice().to_vec(),
                |mut t| {
                    t.copy_from_slice(b.as_slice());
                    t
                },
            );

            self.lazy_transform_slice(a.as_mut_slice());
            self.lazy_transform_slice(bv.as_mut_slice());

            for (ai, &bi) in a.iter_mut().zip(bv.iter()) {
                self.modulus.lazy_reduce_mul_assign(ai, bi);
            }

            self.pool.store(bv);
            self.lazy_inverse_transform_slice(a.as_mut_slice());
        }

        #[inline]
        fn mul_assign(&self, a: &mut Self::CoeffPoly, b: &Self::CoeffPoly) {
            self.lazy_mul_assign(a, b);
        }

        #[inline]
        fn lazy_mul_inplace(
            &self,
            a: &Self::CoeffPoly,
            b: &Self::CoeffPoly,
            c: &mut Self::CoeffPoly,
        ) {
            c.copy_from(a);
            self.lazy_mul_assign(c, b);
        }

        #[inline]
        fn mul_inplace(&self, a: &Self::CoeffPoly, b: &Self::CoeffPoly, c: &mut Self::CoeffPoly) {
            self.lazy_mul_inplace(a, b, c);
        }
    }
}

/// ntt for 64bits
pub mod prime64 {
    use concrete_ntt::prime64::Plan;

    use crate::{
        modulus::BarrettModulus,
        ntt::{NttTable, NumberTheoryTransform},
        polynomial::{FieldNttPolynomial, FieldPolynomial},
        reduce::LazyReduceMulAssign,
        utils::Pool,
        AlgebraError, Field, NttField,
    };

    /// Wrapping concrete NTT for 64bit primes.
    pub struct Concrete64Table<F>
    where
        F: Field<ValueT = u64, Modulus = BarrettModulus<u64>> + NttField<Table = Self>,
    {
        plan: Plan,
        pool: Pool<Vec<u64>>,
        root: <F as Field>::ValueT,
        modulus: <F as Field>::Modulus,
    }

    impl<F> Concrete64Table<F>
    where
        F: Field<ValueT = u64, Modulus = BarrettModulus<u64>> + NttField<Table = Self>,
    {
        /// Create a new NTT table for 64bit prime.
        #[inline]
        pub fn new(modulus: <F as Field>::Modulus, log_n: u32) -> Result<Self, AlgebraError> {
            let plan =
                Plan::try_new(1 << log_n, F::MODULUS_VALUE).ok_or(AlgebraError::NttTableErr)?;
            let root = plan.root();
            let pool = Pool::new_with(2, || vec![0; 1 << log_n]);
            Ok(Self {
                plan,
                pool,
                root,
                modulus,
            })
        }

        /// Get the root of unity.
        #[inline]
        pub fn root(&self) -> <F as Field>::ValueT {
            self.root
        }
    }

    impl<F> NttTable for Concrete64Table<F>
    where
        F: Field<ValueT = u64, Modulus = BarrettModulus<u64>> + NttField<Table = Self>,
    {
        type ValueT = u64;

        type ModulusT = <F as Field>::Modulus;

        #[inline]
        fn new(modulus: Self::ModulusT, log_n: u32) -> Result<Self, AlgebraError> {
            Concrete64Table::new(modulus, log_n)
        }

        #[inline]
        fn dimension(&self) -> usize {
            self.plan.ntt_size()
        }
    }

    impl<F> NumberTheoryTransform for Concrete64Table<F>
    where
        F: Field<ValueT = u64, Modulus = BarrettModulus<u64>> + NttField<Table = Self>,
    {
        type CoeffPoly = FieldPolynomial<F>;

        type NttPoly = FieldNttPolynomial<F>;

        #[inline]
        fn transform_inplace(&self, mut poly: Self::CoeffPoly) -> Self::NttPoly {
            self.transform_slice(poly.as_mut_slice());
            FieldNttPolynomial::new(poly.inner_data())
        }

        #[inline]
        fn inverse_transform_inplace(&self, mut values: Self::NttPoly) -> Self::CoeffPoly {
            self.inverse_transform_slice(values.as_mut_slice());
            FieldPolynomial::new(values.inner_data())
        }

        #[inline]
        fn lazy_transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]) {
            self.plan.fwd(poly);
        }

        #[inline]
        fn transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]) {
            self.plan.fwd(poly);
        }

        #[inline]
        fn lazy_inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]) {
            self.plan.inv(values);
            self.plan.normalize(values);
        }

        #[inline]
        fn inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]) {
            self.plan.inv(values);
            self.plan.normalize(values);
        }

        #[inline]
        fn transform_monomial(
            &self,
            coeff: Self::ValueT,
            degree: usize,
            values: &mut [<Self as NttTable>::ValueT],
        ) {
            self.plan.fwd_monomial(coeff, degree, values);
        }

        #[inline]
        fn transform_coeff_one_monomial(
            &self,
            degree: usize,
            values: &mut [<Self as NttTable>::ValueT],
        ) {
            self.plan.fwd_coeff_one_monomial(degree, values);
        }

        #[inline]
        fn transform_coeff_minus_one_monomial(
            &self,
            degree: usize,
            values: &mut [<Self as NttTable>::ValueT],
        ) {
            self.plan.fwd_coeff_minus_one_monomial(degree, values);
        }

        #[inline]
        fn lazy_mul_assign(&self, a: &mut Self::CoeffPoly, b: &Self::CoeffPoly) {
            let mut bv = self.pool.try_get().map_or_else(
                || b.as_slice().to_vec(),
                |mut t| {
                    t.copy_from_slice(b.as_slice());
                    t
                },
            );

            self.lazy_transform_slice(a.as_mut_slice());
            self.lazy_transform_slice(bv.as_mut_slice());

            for (ai, &bi) in a.iter_mut().zip(bv.iter()) {
                self.modulus.lazy_reduce_mul_assign(ai, bi);
            }

            self.pool.store(bv);
            self.lazy_inverse_transform_slice(a.as_mut_slice());
        }

        #[inline]
        fn mul_assign(&self, a: &mut Self::CoeffPoly, b: &Self::CoeffPoly) {
            self.lazy_mul_assign(a, b);
        }

        #[inline]
        fn lazy_mul_inplace(
            &self,
            a: &Self::CoeffPoly,
            b: &Self::CoeffPoly,
            c: &mut Self::CoeffPoly,
        ) {
            c.copy_from(a);
            self.lazy_mul_assign(c, b);
        }

        #[inline]
        fn mul_inplace(&self, a: &Self::CoeffPoly, b: &Self::CoeffPoly, c: &mut Self::CoeffPoly) {
            self.lazy_mul_inplace(a, b, c);
        }
    }
}
