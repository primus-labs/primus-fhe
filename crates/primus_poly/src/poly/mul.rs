use primus_data::{Data, DataMut};
use primus_factor::FactorSliceOps;
use primus_integer::FheUint;
use primus_reduce::{
    ReduceAdd, ReduceAddSlice, ReduceMul, ReduceMulAdd, ReduceMulAddSlice, ReduceMulSlice,
    ReduceNegSlice, ReduceSub, ReduceSubAssign, ReduceSubSlice, RingContext,
};

use super::Polynomial;

impl<S, T> Polynomial<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Accumulates `self += rhs * X^exponent` in `Z_q[X]/(X^N + 1)`.
    ///
    /// Both polynomials must have the same nonzero power-of-two length `N`.
    /// `exponent` must be in `[0, 2N)`. Input and accumulator must be canonical
    /// residues; results are canonical. No temporary polynomial is allocated.
    #[inline]
    pub fn add_mul_monomial_assign<M, A>(
        &mut self,
        rhs: &Polynomial<A>,
        exponent: usize,
        modulus: M,
    ) where
        M: Copy + ReduceAddSlice<T> + ReduceSubSlice<T>,
        A: Data<Elem = T>,
    {
        add_mul_monomial_assign_kernel(self.as_mut_view(), rhs.as_view(), exponent, modulus);
    }

    /// Accumulates `self += first * X^first_exponent + second * X^second_exponent` modulo `X^N + 1`.
    ///
    /// Each coefficient is reduced after the first contribution and again after
    /// the second, preserving canonical output. Both contributions share one
    /// output traversal; no temporary polynomial or scratch allocation is needed.
    ///
    /// # Correctness
    ///
    /// All three polynomials must have the same nonzero power-of-two length `N`,
    /// and both exponents must be in `[0, 2N)`. Inputs and the initialized
    /// accumulator must be canonical for `modulus`.
    ///
    /// # Panics
    ///
    /// Panics if the polynomial length is zero. Debug builds also check lengths
    /// and exponent ranges. Violating these conditions can panic after partial
    /// writes in release builds.
    #[inline]
    pub fn add_mul_monomial_pair_assign<M, A, B>(
        &mut self,
        first: &Polynomial<A>,
        first_exponent: usize,
        second: &Polynomial<B>,
        second_exponent: usize,
        modulus: M,
    ) where
        M: Copy + ReduceAdd<T, Output = T> + ReduceSub<T, Output = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
    {
        let n = self.len();
        crate::add_mul_monomial_pair_assign(
            self.as_mut(),
            first.as_ref(),
            first_exponent,
            second.as_ref(),
            second_exponent,
            n,
            modulus,
        );
    }

    /// Performs `self * scalar` according to `modulus`.
    #[must_use]
    #[inline]
    pub fn mul_scalar<M>(mut self, scalar: T, modulus: M) -> Self
    where
        M: Copy + ReduceMulSlice<T>,
    {
        self.mul_scalar_assign(scalar, modulus);
        self
    }

    /// Performs `self * factor` according to `modulus`.
    #[must_use]
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
        A: Data<Elem = T>,
    {
        modulus.reduce_add_mul_scalar_slice_assign(self.as_mut(), rhs.as_ref(), scalar);
    }

    /// Performs `self *= factor` according to `modulus`.
    #[inline]
    pub fn mul_factor_assign<F>(&mut self, factor: F, modulus: T)
    where
        F: FactorSliceOps<T>,
    {
        factor.factor_mul_slice_assign(self.as_mut(), modulus)
    }

    /// Performs `self += factor * rhs` according to `modulus`.
    #[inline]
    pub fn add_mul_factor_assign<F, A>(&mut self, rhs: &Polynomial<A>, factor: F, modulus: T)
    where
        F: FactorSliceOps<T>,
        A: Data<Elem = T>,
    {
        factor.add_factor_mul_slice_assign(self.as_mut(), rhs.as_ref(), modulus);
    }

    /// Multiplies `self` by the monomial `X^r` in the ring `Z_modulus[X]/(X^N + 1)`, in place.
    ///
    /// `r` must belong to `[0, 2N)`.
    pub fn mul_monomial_assign<M>(&mut self, r: usize, modulus: M)
    where
        M: Copy + ReduceNegSlice<T>,
    {
        mul_monomial_assign_kernel(self.as_mut_view(), r, modulus);
    }
}

impl<S, T> Polynomial<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Multiplies `self` by `X^exponent` in `Z_q[X]/(X^N + 1)` and writes the result.
    ///
    /// `exponent` must belong to `[0, 2N)`.
    #[inline]
    pub fn mul_monomial_to<M, A>(&self, exponent: usize, output: &mut Polynomial<A>, modulus: M)
    where
        M: RingContext<T>,
        A: DataMut<Elem = T>,
    {
        monomial_to::<false, _, _>(self.as_view(), exponent, output.as_mut_view(), modulus);
    }

    /// Computes `output = self * (X^exponent - 1)` in `Z_q[X]/(X^N + 1)`.
    ///
    /// `exponent` must belong to `[0, 2N)`. Rotation and subtraction are
    /// fused into one coefficient pass.
    #[inline]
    pub fn mul_monomial_sub_one_to<M, A>(
        &self,
        exponent: usize,
        output: &mut Polynomial<A>,
        modulus: M,
    ) where
        M: RingContext<T>,
        A: DataMut<Elem = T>,
    {
        monomial_to::<true, _, _>(self.as_view(), exponent, output.as_mut_view(), modulus);
    }

    /// Performs a naive negacyclic multiplication and overwrites `output`.
    ///
    /// # Correctness
    ///
    /// All three polynomials have the same coefficient count `N`; arbitrary
    /// lengths are supported, and empty inputs are a no-op. Coefficients satisfy
    /// the selected modulus operations' input ranges. The product is reduced
    /// modulo `X^N + 1`, with no transform or scratch allocation.
    pub fn naive_mul_to<M, A, B>(&self, rhs: &Polynomial<A>, output: &mut Polynomial<B>, modulus: M)
    where
        M: Copy + ReduceSubAssign<T> + ReduceMul<T, Output = T> + ReduceMulAdd<T, Output = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        naive_mul_to_kernel(self.as_view(), rhs.as_view(), output.as_mut_view(), modulus);
    }

    /// Performs `result = self * scalar` according to `modulus`.
    #[inline]
    pub fn mul_scalar_to<M, A>(&self, scalar: T, output: &mut Polynomial<A>, modulus: M)
    where
        M: Copy + ReduceMulSlice<T>,
        A: DataMut<Elem = T>,
    {
        modulus.reduce_mul_scalar_slice_to(self.as_ref(), scalar, output.as_mut());
    }

    /// Performs `result = self * factor` according to `modulus`.
    #[inline]
    pub fn mul_factor_to<F, A>(&self, factor: F, output: &mut Polynomial<A>, modulus: T)
    where
        F: FactorSliceOps<T>,
        A: DataMut<Elem = T>,
    {
        factor.factor_mul_slice_to(self.as_ref(), output.as_mut(), modulus);
    }
}

// X^N = -1 gives opposite signs to the wrapped tail and the remaining head.
#[inline]
fn add_mul_monomial_assign_kernel<T, M>(
    mut acc: Polynomial<&mut [T]>,
    rhs: Polynomial<&[T]>,
    exponent: usize,
    modulus: M,
) where
    T: FheUint,
    M: Copy + ReduceAddSlice<T> + ReduceSubSlice<T>,
{
    let n = acc.len();
    debug_assert!(n > 0 && n.is_power_of_two(), "invalid polynomial length");
    debug_assert_eq!(rhs.len(), n, "polynomial length mismatch");
    debug_assert!(exponent / n < 2, "monomial exponent must be less than 2N");
    let negate = exponent >= n;
    let shift = if negate { exponent - n } else { exponent };
    let (head, tail) = rhs.as_ref().split_at(n - shift);
    let (wrapped, rest) = acc.as_mut().split_at_mut(shift);
    if negate {
        modulus.reduce_add_slice_assign(wrapped, tail);
        modulus.reduce_sub_slice_assign(rest, head);
    } else {
        modulus.reduce_sub_slice_assign(wrapped, tail);
        modulus.reduce_add_slice_assign(rest, head);
    }
}

// Rotation moves the wrapped coefficients to the front. A global X^N factor
// swaps which contiguous interval must be negated.
#[inline]
fn mul_monomial_assign_kernel<T, M>(mut polynomial: Polynomial<&mut [T]>, r: usize, modulus: M)
where
    T: FheUint,
    M: Copy + ReduceNegSlice<T>,
{
    let poly_length = polynomial.len();
    let coefficients = polynomial.as_mut();

    if r < poly_length {
        coefficients.rotate_right(r);
        modulus.reduce_neg_slice_assign(&mut coefficients[..r]);
    } else {
        debug_assert!(r < poly_length * 2);
        let r = r - poly_length;
        coefficients.rotate_right(r);
        modulus.reduce_neg_slice_assign(&mut coefficients[r..]);
    }
}

// Split the rotation at its wrap point: crossing X^N changes the sign.
// Subtract the unrotated coefficient in the same pass for (X^exponent - 1).
#[inline]
fn monomial_to<const SUBTRACT_SELF: bool, T, M>(
    input: Polynomial<&[T]>,
    exponent: usize,
    mut output: Polynomial<&mut [T]>,
    modulus: M,
) where
    T: FheUint,
    M: RingContext<T>,
{
    let input = input.as_ref();
    let output = output.as_mut();
    let poly_length = input.len();

    debug_assert!(poly_length > 0 && poly_length.is_power_of_two());
    debug_assert!(exponent < 2 * poly_length);
    debug_assert_eq!(output.len(), poly_length);

    let shift = exponent & (poly_length - 1);
    let negate_rotation = exponent >= poly_length;
    let tail_len = poly_length - shift;

    if SUBTRACT_SELF {
        if negate_rotation {
            for destination in 0..shift {
                output[destination] =
                    modulus.reduce_sub(input[tail_len + destination], input[destination]);
            }
            for destination in shift..poly_length {
                output[destination] = modulus.reduce_sub(
                    modulus.reduce_neg(input[destination - shift]),
                    input[destination],
                );
            }
        } else {
            for destination in 0..shift {
                output[destination] = modulus.reduce_sub(
                    modulus.reduce_neg(input[tail_len + destination]),
                    input[destination],
                );
            }
            for destination in shift..poly_length {
                output[destination] =
                    modulus.reduce_sub(input[destination - shift], input[destination]);
            }
        }
    } else {
        output[..shift].copy_from_slice(&input[tail_len..]);
        output[shift..].copy_from_slice(&input[..tail_len]);
        if negate_rotation {
            modulus.reduce_neg_slice_assign(&mut output[shift..]);
        } else {
            modulus.reduce_neg_slice_assign(&mut output[..shift]);
        }
    }
}

// Compute degrees below N first, then subtract higher-degree products because
// X^N = -1. Keep the reduction order and the empty-input no-op unchanged.
fn naive_mul_to_kernel<T, M>(
    lhs: Polynomial<&[T]>,
    rhs: Polynomial<&[T]>,
    mut output: Polynomial<&mut [T]>,
    modulus: M,
) where
    T: FheUint,
    M: Copy + ReduceSubAssign<T> + ReduceMul<T, Output = T> + ReduceMulAdd<T, Output = T>,
{
    let a: &[T] = lhs.as_ref();
    let b: &[T] = rhs.as_ref();
    let c: &mut [T] = output.as_mut();

    let coeff_count = a.len();
    debug_assert_eq!(coeff_count, b.len());
    debug_assert_eq!(coeff_count, c.len());

    if coeff_count == 0 {
        return;
    }

    for i in 0..coeff_count {
        c[i] = modulus.reduce_mul(a[0], b[i]);
        for j in 1..=i {
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
