pub use concrete_ntt::prime32;
pub use concrete_ntt::prime64;

mod impl_ntt_prime32 {
    use std::mem::transmute;

    use concrete_ntt::prime32::Plan;

    use crate::{
        transformation::{AbstractNTT, MonomialNTT},
        Field, NTTField,
    };

    impl<F> AbstractNTT<F> for Plan
    where
        F: NTTField + Field<Value = u32>,
    {
        #[inline]
        fn transform_slice(&self, polynomial_slice: &mut [F]) {
            self.fwd(unsafe { transmute::<&mut [F], &mut [u32]>(polynomial_slice) });
        }

        #[inline]
        fn inverse_transform_slice(&self, ntt_polynomial_slice: &mut [F]) {
            let values = unsafe { transmute::<&mut [F], &mut [u32]>(ntt_polynomial_slice) };
            self.inv(values);
            self.normalize(values);
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
        Field, NTTField,
    };

    impl<F> AbstractNTT<F> for Plan
    where
        F: NTTField + Field<Value = u64>,
    {
        #[inline]
        fn transform_slice(&self, polynomial_slice: &mut [F]) {
            self.fwd(unsafe { transmute::<&mut [F], &mut [u64]>(polynomial_slice) });
        }

        #[inline]
        fn inverse_transform_slice(&self, ntt_polynomial_slice: &mut [F]) {
            self.inv(unsafe { transmute::<&mut [F], &mut [u64]>(ntt_polynomial_slice) })
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
