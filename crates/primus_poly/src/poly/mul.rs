use num_traits::ConstZero;
use primus_data::{Data, DataMut, RawData};
use primus_factor::FactorSliceOps;
use primus_integer::FheUint;
use primus_reduce::{
    ReduceMul, ReduceMulAdd, ReduceMulAddSlice, ReduceMulSlice, ReduceNegSlice, ReduceSubAssign,
};

use super::Polynomial;

impl<S, T> Polynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Performs `self * scalar` according to `modulus`.
    #[inline]
    pub fn mul_scalar<M>(mut self, scalar: T, modulus: M) -> Self
    where
        M: Copy + ReduceMulSlice<T>,
    {
        self.mul_scalar_assign(scalar, modulus);
        self
    }

    /// Performs `self * factor` according to `modulus`.
    #[inline]
    pub fn mul_factor<F>(mut self, factor: F, modulus: T) -> Self
    where
        F: FactorSliceOps<T>,
    {
        self.mul_factor_assign(factor, modulus);
        self
    }

    /// Performs `self *= scalar` according to `modulus`.
    #[inline]
    pub fn mul_scalar_assign<M>(&mut self, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulSlice<T>,
    {
        modulus.reduce_mul_scalar_slice_assign(self.as_mut(), scalar);
    }

    /// Performs `self += scalar * rhs` according to `modulus`.
    #[inline]
    pub fn add_mul_scalar_assign<M, A>(&mut self, rhs: &Polynomial<A>, scalar: T, modulus: M)
    where
        M: Copy + ReduceMulAddSlice<T>,
        A: RawData<Elem = T> + Data,
    {
        modulus.reduce_add_mul_scalar_slice_assign(self.as_mut(), rhs.as_ref(), scalar);
    }

    /// Performs `self *= scalar` according to `modulus`.
    #[inline]
    pub fn mul_factor_assign<F>(&mut self, factor: F, modulus: T)
    where
        F: FactorSliceOps<T>,
    {
        factor.factor_mul_slice_assign(self.as_mut(), modulus)
    }

    /// Performs `self += scalar * rhs` according to `modulus`.
    #[inline]
    pub fn add_mul_factor_assign<F, A>(&mut self, rhs: &Polynomial<A>, factor: F, modulus: T)
    where
        F: FactorSliceOps<T>,
        A: RawData<Elem = T> + Data,
    {
        factor.add_factor_mul_slice_assign(self.as_mut(), rhs.as_ref(), modulus);
    }

    /// Multiplies `self` by the monomial `X^r` in the ring `Z_modulus[X]/(X^N + 1)`, in place.
    pub fn mul_monomial_assign<M>(&mut self, r: usize, modulus: M)
    where
        M: Copy + ReduceNegSlice<T>,
    {
        let poly_length = self.poly_length();

        if r < poly_length {
            let rotate = |poly: &mut [T], modulus: M| {
                poly.rotate_right(r);
                modulus.reduce_neg_slice_assign(&mut poly[0..r]);
            };

            rotate(self.as_mut_slice(), modulus)
        } else {
            debug_assert!(r < poly_length * 2);
            let r = r - poly_length;

            let rotate = |poly: &mut [T], modulus: M| {
                poly.rotate_right(r);
                modulus.reduce_neg_slice_assign(&mut poly[r..]);
            };

            rotate(self.as_mut_slice(), modulus)
        }
    }
}

impl<S, T> Polynomial<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// A naive multiplication over polynomial.
    ///
    /// Performs `output = self * rhs` in `Z_modulus[X]/(X^N + 1)`.
    pub fn naive_mul_to<M, A, B>(&self, rhs: &Polynomial<A>, output: &mut Polynomial<B>, modulus: M)
    where
        M: Copy + ReduceSubAssign<T> + ReduceMul<T, Output = T> + ReduceMulAdd<T, Output = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let a: &[T] = self.as_ref();
        let b: &[T] = rhs.as_ref();
        let c: &mut [T] = output.as_mut();

        let coeff_count = a.len();
        debug_assert_eq!(coeff_count, b.len());
        debug_assert_eq!(coeff_count, c.len());

        // The loops below accumulate into `c`, so a caller-supplied buffer has
        // to start from zero for this to be an assignment like the other `_to`
        // methods.
        c.fill(<T as ConstZero>::ZERO);

        for i in 0..coeff_count {
            for j in 0..=i {
                c[i] = modulus.reduce_mul_add(a[j], b[i - j], c[i]);
            }
        }

        // mod (x^n + 1)
        for i in coeff_count..coeff_count * 2 - 1 {
            let k = i - coeff_count;
            for j in i - coeff_count + 1..coeff_count {
                modulus.reduce_sub_assign(&mut c[k], modulus.reduce_mul(a[j], b[i - j]));
            }
        }
    }

    /// Performs `result = self * scalar` according to `modulus`.
    #[inline]
    pub fn mul_scalar_to<M, A>(&self, scalar: T, output: &mut Polynomial<A>, modulus: M)
    where
        M: Copy + ReduceMulSlice<T>,
        A: RawData<Elem = T> + DataMut,
    {
        modulus.reduce_mul_scalar_slice_to(self.as_ref(), scalar, output.as_mut());
    }

    /// Performs `result = self * scalar` according to `modulus`.
    #[inline]
    pub fn mul_factor_to<F, A>(&self, factor: F, output: &mut Polynomial<A>, modulus: T)
    where
        F: FactorSliceOps<T>,
        A: RawData<Elem = T> + DataMut,
    {
        factor.factor_mul_slice_to(self.as_ref(), output.as_mut(), modulus);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primus_modulus::BarrettModulus;

    const MODULUS: u64 = 132120577;

    // (1 + 2X) * (3 + 4X) = 3 + 10X + 8X^2, and X^2 = -1 in Z[X]/(X^2 + 1),
    // so the product is -5 + 10X.
    fn operands() -> (Polynomial<Vec<u64>>, Polynomial<Vec<u64>>, [u64; 2]) {
        (
            Polynomial::new(vec![1u64, 2]),
            Polynomial::new(vec![3u64, 4]),
            [MODULUS - 5, 10],
        )
    }

    #[test]
    fn naive_mul_to_writes_the_product() {
        let modulus = BarrettModulus::<u64>::new(MODULUS);
        let (a, b, expected) = operands();

        let mut output = Polynomial::<Vec<u64>>::zero(2);
        a.naive_mul_to(&b, &mut output, modulus);

        assert_eq!(output.as_ref(), expected.as_slice());
    }

    // The other `_to` methods assign, so an output buffer that already holds
    // data must be overwritten rather than accumulated into.
    #[test]
    fn naive_mul_to_overwrites_a_dirty_output() {
        let modulus = BarrettModulus::<u64>::new(MODULUS);
        let (a, b, expected) = operands();

        let mut output = Polynomial::new(vec![7u64, 9]);
        a.naive_mul_to(&b, &mut output, modulus);

        assert_eq!(output.as_ref(), expected.as_slice());
    }
}
