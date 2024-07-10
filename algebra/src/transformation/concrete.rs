pub use concrete_ntt::prime32;
pub use concrete_ntt::prime64;

mod impl_ntt_prime32 {
    use std::mem::transmute;

    use concrete_ntt::prime32::Plan;

    use crate::{
        transformation::{AbstractNTT, MonomialNTT},
        Field, NTTField, NTTPolynomial, Polynomial,
    };

    impl<F> AbstractNTT<F> for Plan
    where
        F: NTTField + Field<Value = u32>,
    {
        #[inline]
        fn transform(&self, polynomial: &Polynomial<F>) -> NTTPolynomial<F> {
            self.transform_inplace(polynomial.clone())
        }

        #[inline]
        fn transform_inplace(&self, mut polynomial: Polynomial<F>) -> NTTPolynomial<F> {
            self.transform_slice(polynomial.as_mut_slice());
            NTTPolynomial::<F>::new(polynomial.data())
        }

        #[inline]
        fn inverse_transform(&self, ntt_polynomial: &NTTPolynomial<F>) -> Polynomial<F> {
            self.inverse_transform_inplace(ntt_polynomial.clone())
        }

        #[inline]
        fn inverse_transform_inplace(&self, mut ntt_polynomial: NTTPolynomial<F>) -> Polynomial<F> {
            self.inverse_transform_slice(ntt_polynomial.as_mut_slice());
            Polynomial::<F>::new(ntt_polynomial.data())
        }

        #[inline]
        fn transform_slice(&self, polynomial_slice: &mut [F]) {
            self.fwd(unsafe { transmute(polynomial_slice) });
        }

        #[inline]
        fn inverse_transform_slice(&self, ntt_polynomial_slice: &mut [F]) {
            self.inv(unsafe { transmute(ntt_polynomial_slice) })
        }
    }

    impl<F> MonomialNTT<F> for Plan
    where
        F: NTTField + Field<Value = u32>,
    {
        #[inline]
        fn transform_monomial(&self, coeff: F, degree: usize, values: &mut [F]) {
            if coeff == F::ZERO {
                values.fill(F::ZERO);
                return;
            }

            if degree == 0 {
                values.fill(coeff);
                return;
            }

            let values = unsafe { transmute::<&mut [F], &mut [u32]>(values) };
            values.fill(0);
            if degree < values.len() {
                values[degree] = coeff.get();
            } else {
                values[degree - values.len()] = (-coeff).get();
            }

            self.fwd(values)
        }

        #[inline]
        fn transform_coeff_one_monomial(&self, degree: usize, values: &mut [F]) {
            if degree == 0 {
                values.fill(F::ONE);
                return;
            }

            let values = unsafe { transmute::<&mut [F], &mut [u32]>(values) };
            values.fill(0);
            if degree < values.len() {
                values[degree] = 1;
            } else {
                values[degree - values.len()] = self.modulus() - 1;
            }

            self.fwd(values)
        }
    }
}

mod impl_ntt_prime64 {
    use std::mem::transmute;

    use concrete_ntt::prime64::Plan;

    use crate::{
        transformation::{AbstractNTT, MonomialNTT},
        Field, NTTField, NTTPolynomial, Polynomial,
    };

    impl<F> AbstractNTT<F> for Plan
    where
        F: NTTField + Field<Value = u64>,
    {
        #[inline]
        fn transform(&self, polynomial: &Polynomial<F>) -> NTTPolynomial<F> {
            self.transform_inplace(polynomial.clone())
        }

        #[inline]
        fn transform_inplace(&self, mut polynomial: Polynomial<F>) -> NTTPolynomial<F> {
            self.transform_slice(polynomial.as_mut_slice());
            NTTPolynomial::<F>::new(polynomial.data())
        }

        #[inline]
        fn inverse_transform(&self, ntt_polynomial: &NTTPolynomial<F>) -> Polynomial<F> {
            self.inverse_transform_inplace(ntt_polynomial.clone())
        }

        #[inline]
        fn inverse_transform_inplace(&self, mut ntt_polynomial: NTTPolynomial<F>) -> Polynomial<F> {
            self.inverse_transform_slice(ntt_polynomial.as_mut_slice());
            Polynomial::<F>::new(ntt_polynomial.data())
        }

        #[inline]
        fn transform_slice(&self, polynomial_slice: &mut [F]) {
            self.fwd(unsafe { transmute(polynomial_slice) });
        }

        #[inline]
        fn inverse_transform_slice(&self, ntt_polynomial_slice: &mut [F]) {
            self.inv(unsafe { transmute(ntt_polynomial_slice) })
        }
    }

    impl<F> MonomialNTT<F> for Plan
    where
        F: NTTField + Field<Value = u64>,
    {
        #[inline]
        fn transform_monomial(&self, coeff: F, degree: usize, values: &mut [F]) {
            if coeff == F::ZERO {
                values.fill(F::ZERO);
                return;
            }

            if degree == 0 {
                values.fill(coeff);
                return;
            }

            let values = unsafe { transmute::<&mut [F], &mut [u64]>(values) };
            values.fill(0);
            if degree < values.len() {
                values[degree] = coeff.get();
            } else {
                values[degree - values.len()] = (-coeff).get();
            }

            self.fwd(values)
        }

        #[inline]
        fn transform_coeff_one_monomial(&self, degree: usize, values: &mut [F]) {
            if degree == 0 {
                values.fill(F::ONE);
                return;
            }

            let values = unsafe { transmute::<&mut [F], &mut [u64]>(values) };
            values.fill(0);
            if degree < values.len() {
                values[degree] = 1;
            } else {
                values[degree - values.len()] = self.modulus() - 1;
            }

            self.fwd(values)
        }
    }
}
