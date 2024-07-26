/// ntt for 32bits
pub mod prime32 {
    use std::mem::transmute;

    use concrete_ntt::prime32::Plan;

    use crate::{
        transformation::{AbstractNTT, MonomialNTT},
        AlgebraError, Field, NTTField,
    };

    /// Wrapping concrete NTT for 32bit primes.
    pub struct ConcreteTable<F>
    where
        F: NTTField<Table = Self> + Field<Value = u32>,
    {
        root: F,
        plan: Plan,
    }

    impl<F> ConcreteTable<F>
    where
        F: NTTField<Table = Self> + Field<Value = u32>,
    {
        /// Instantiation
        #[inline]
        pub fn new(log_n: u32) -> Result<Self, AlgebraError> {
            let plan =
                Plan::try_new(1 << log_n, F::MODULUS_VALUE).ok_or(AlgebraError::NTTTableError)?;
            let root = F::new(plan.root());
            Ok(Self { root, plan })
        }
    }

    impl<F> AbstractNTT<F> for ConcreteTable<F>
    where
        F: NTTField<Table = Self> + Field<Value = u32>,
    {
        #[inline]
        fn root(&self) -> F {
            self.root
        }

        #[inline]
        fn transform_slice(&self, polynomial_slice: &mut [F]) {
            self.plan
                .fwd(unsafe { transmute::<&mut [F], &mut [u32]>(polynomial_slice) });
        }

        #[inline]
        fn inverse_transform_slice(&self, ntt_polynomial_slice: &mut [F]) {
            let values = unsafe { transmute::<&mut [F], &mut [u32]>(ntt_polynomial_slice) };
            self.plan.inv(values);
            self.plan.normalize(values);
        }
    }

    impl<F> MonomialNTT<F> for ConcreteTable<F>
    where
        F: NTTField<Table = Self> + Field<Value = u32>,
    {
        #[inline]
        fn transform_monomial(&self, coeff: F, degree: usize, values: &mut [F]) {
            let values = unsafe { transmute::<&mut [F], &mut [u32]>(values) };
            self.plan.fwd_monomial(coeff.value(), degree, values);
        }

        #[inline]
        fn transform_coeff_one_monomial(&self, degree: usize, values: &mut [F]) {
            let values = unsafe { transmute::<&mut [F], &mut [u32]>(values) };
            self.plan.fwd_coeff_one_monomial(degree, values);
        }

        #[inline]
        fn transform_coeff_neg_one_monomial(&self, degree: usize, values: &mut [F]) {
            let values = unsafe { transmute::<&mut [F], &mut [u32]>(values) };
            self.plan.fwd_coeff_neg_one_monomial(degree, values);
        }
    }
}

/// ntt for 64bits
pub mod prime64 {
    use std::mem::transmute;

    use concrete_ntt::prime64::Plan;

    use crate::{
        transformation::{AbstractNTT, MonomialNTT},
        AlgebraError, Field, NTTField,
    };

    /// Wrapping concrete NTT for 64bit primes.
    pub struct ConcreteTable<F>
    where
        F: NTTField<Table = Self> + Field<Value = u64>,
    {
        root: F,
        plan: Plan,
    }

    impl<F> ConcreteTable<F>
    where
        F: NTTField<Table = Self> + Field<Value = u64>,
    {
        /// Instantiation
        #[inline]
        pub fn new(log_n: u32) -> Result<Self, AlgebraError> {
            let plan =
                Plan::try_new(1 << log_n, F::MODULUS_VALUE).ok_or(AlgebraError::NTTTableError)?;
            let root = F::new(plan.root());
            Ok(Self { root, plan })
        }
    }

    impl<F> AbstractNTT<F> for ConcreteTable<F>
    where
        F: NTTField<Table = Self> + Field<Value = u64>,
    {
        #[inline]
        fn root(&self) -> F {
            self.root
        }

        #[inline]
        fn transform_slice(&self, polynomial_slice: &mut [F]) {
            self.plan
                .fwd(unsafe { transmute::<&mut [F], &mut [u64]>(polynomial_slice) });
        }

        #[inline]
        fn inverse_transform_slice(&self, ntt_polynomial_slice: &mut [F]) {
            let values = unsafe { transmute::<&mut [F], &mut [u64]>(ntt_polynomial_slice) };
            self.plan.inv(values);
            self.plan.normalize(values);
        }
    }

    impl<F> MonomialNTT<F> for ConcreteTable<F>
    where
        F: NTTField<Table = Self> + Field<Value = u64>,
    {
        #[inline]
        fn transform_monomial(&self, coeff: F, degree: usize, values: &mut [F]) {
            let values = unsafe { transmute::<&mut [F], &mut [u64]>(values) };
            self.plan.fwd_monomial(coeff.value(), degree, values);
        }

        #[inline]
        fn transform_coeff_one_monomial(&self, degree: usize, values: &mut [F]) {
            let values = unsafe { transmute::<&mut [F], &mut [u64]>(values) };
            self.plan.fwd_coeff_one_monomial(degree, values);
        }

        #[inline]
        fn transform_coeff_neg_one_monomial(&self, degree: usize, values: &mut [F]) {
            let values = unsafe { transmute::<&mut [F], &mut [u64]>(values) };
            self.plan.fwd_coeff_neg_one_monomial(degree, values);
        }
    }
}
