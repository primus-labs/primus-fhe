/// ntt for 32bits
pub mod prime32 {

    use concrete_ntt::prime32::Plan;
    use primus_data::{DataMut, RawData};
    use primus_poly::{NttPolynomial, Polynomial};
    use primus_reduce::FieldContext;

    use crate::{NttError, NttTable};

    /// Wrapping concrete NTT for 32bit primes.
    pub struct Concrete32Table {
        plan: Plan,
        root: u32,
        modulus: u32,
    }

    impl Concrete32Table {
        /// Get the root of unity.
        #[inline]
        pub fn root(&self) -> u32 {
            self.root
        }

        /// Returns the modulus.
        #[inline]
        pub fn modulus(&self) -> u32 {
            self.modulus
        }
    }

    impl NttTable for Concrete32Table {
        type ValueT = u32;

        #[inline]
        fn new<M>(log_n: u32, modulus: M) -> Result<Self, NttError<Self::ValueT>>
        where
            M: FieldContext<Self::ValueT>,
        {
            let modulus = unsafe { modulus.value_unchecked() };
            let plan = Plan::try_new(1 << log_n, modulus).ok_or(NttError::NttTableErr)?;
            let root = plan.root();

            Ok(Self {
                plan,
                modulus,
                root,
            })
        }

        #[inline]
        fn poly_length(&self) -> usize {
            self.plan.ntt_size()
        }

        #[inline]
        fn transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
            &self,
            mut poly: Polynomial<S>,
        ) -> NttPolynomial<S> {
            self.transform_slice(poly.as_mut_slice());
            NttPolynomial::new(poly.0)
        }

        #[inline]
        fn inverse_transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
            &self,
            mut values: NttPolynomial<S>,
        ) -> Polynomial<S> {
            self.inverse_transform_slice(values.as_mut_slice());
            Polynomial::new(values.0)
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
}

/// ntt for 64bits
pub mod prime64 {
    use concrete_ntt::prime64::Plan;
    use primus_data::{DataMut, RawData};
    use primus_poly::{NttPolynomial, Polynomial};

    use crate::{NttError, NttTable};

    /// Wrapping concrete NTT for 64bit primes.
    #[derive(Clone)]
    pub struct Concrete64Table {
        plan: Plan,
        root: u64,
        modulus: u64,
    }

    impl Concrete64Table {
        /// Get the root of unity.
        #[inline]
        pub fn root(&self) -> u64 {
            self.root
        }

        /// Returns the modulus.
        #[inline]
        pub fn modulus(&self) -> u64 {
            self.modulus
        }
    }

    impl NttTable for Concrete64Table {
        type ValueT = u64;

        fn new<M>(log_n: u32, modulus: M) -> Result<Self, NttError<Self::ValueT>>
        where
            M: primus_reduce::FieldContext<Self::ValueT>,
        {
            let modulus = unsafe { modulus.value_unchecked() };
            let plan = Plan::try_new(1 << log_n, modulus).ok_or(NttError::NttTableErr)?;
            let root = plan.root();

            Ok(Self {
                plan,
                root,
                modulus,
            })
        }

        fn poly_length(&self) -> usize {
            self.plan.ntt_size()
        }

        #[inline]
        fn transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
            &self,
            mut poly: Polynomial<S>,
        ) -> NttPolynomial<S> {
            self.transform_slice(poly.as_mut_slice());
            NttPolynomial::new(poly.0)
        }

        #[inline]
        fn inverse_transform_inplace<S: RawData<Elem = Self::ValueT> + DataMut>(
            &self,
            mut values: NttPolynomial<S>,
        ) -> Polynomial<S> {
            self.inverse_transform_slice(values.as_mut_slice());
            Polynomial::new(values.0)
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
}
