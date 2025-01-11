/// ntt for 32bits
pub mod prime32 {

    use concrete_ntt::prime32::Plan;

    use crate::{
        arith::PrimitiveRoot,
        ntt::{NttTable, NumberTheoryTransform},
        polynomial::{FieldNttPolynomial, FieldPolynomial},
        reduce::Modulus,
        AlgebraError, Field, NttField,
    };

    /// Wrapping concrete NTT for 32bit primes.
    #[derive(Clone)]
    pub struct Concrete32Table<F>
    where
        F: NttField<Table = Self> + Field<ValueT = u32>,
    {
        root: <F as Field>::ValueT,
        plan: Plan,
    }

    impl<F> NumberTheoryTransform for Concrete32Table<F>
    where
        F: NttField<Table = Self> + Field<ValueT = u32>,
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
    }

    impl<F> NttTable for Concrete32Table<F>
    where
        F: NttField<Table = Self> + Field<ValueT = u32>,
    {
        type ValueT = u32;

        #[inline]
        fn new<M>(_modulus: M, log_n: u32) -> Result<Self, AlgebraError>
        where
            M: Modulus<Self::ValueT> + PrimitiveRoot<Self::ValueT>,
        {
            Concrete32Table::new(log_n)
        }

        #[inline]
        fn dimension(&self) -> usize {
            self.plan.ntt_size()
        }
    }

    impl<F> Concrete32Table<F>
    where
        F: NttField<Table = Self> + Field<ValueT = u32>,
    {
        /// Create a new NTT table for 32bit prime.
        #[inline]
        pub fn new(log_n: u32) -> Result<Self, AlgebraError> {
            let plan =
                Plan::try_new(1 << log_n, F::MODULUS_VALUE).ok_or(AlgebraError::NttTableErr)?;
            let root = plan.root();
            Ok(Self { root, plan })
        }

        /// Get the root of unity.
        #[inline]
        pub fn root(&self) -> <F as Field>::ValueT {
            self.root
        }
    }
}

/// ntt for 64bits
pub mod prime64 {
    use concrete_ntt::prime64::Plan;

    use crate::{
        ntt::{NttTable, NumberTheoryTransform},
        polynomial::{FieldNttPolynomial, FieldPolynomial},
        AlgebraError, Field, NttField,
    };

    /// Wrapping concrete NTT for 64bit primes.
    #[derive(Clone)]
    pub struct Concrete64Table<F>
    where
        F: NttField<Table = Self> + Field<ValueT = u64>,
    {
        root: <F as Field>::ValueT,
        plan: Plan,
    }

    impl<F> NumberTheoryTransform for Concrete64Table<F>
    where
        F: NttField<Table = Self> + Field<ValueT = u64>,
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
    }

    impl<F> NttTable for Concrete64Table<F>
    where
        F: NttField<Table = Self> + Field<ValueT = u64>,
    {
        type ValueT = u64;

        #[inline]
        fn new<M>(_modulus: M, log_n: u32) -> Result<Self, AlgebraError>
        where
            M: crate::reduce::Modulus<Self::ValueT> + crate::arith::PrimitiveRoot<Self::ValueT>,
        {
            Concrete64Table::new(log_n)
        }

        #[inline]
        fn dimension(&self) -> usize {
            self.plan.ntt_size()
        }
    }

    impl<F> Concrete64Table<F>
    where
        F: NttField<Table = Self> + Field<ValueT = u64>,
    {
        /// Create a new NTT table for 64bit prime.
        #[inline]
        pub fn new(log_n: u32) -> Result<Self, AlgebraError> {
            let plan =
                Plan::try_new(1 << log_n, F::MODULUS_VALUE).ok_or(AlgebraError::NttTableErr)?;
            let root = plan.root();
            Ok(Self { root, plan })
        }

        /// Get the root of unity.
        #[inline]
        pub fn root(&self) -> <F as Field>::ValueT {
            self.root
        }
    }
}
