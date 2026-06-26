use primus_data::{DataMut, RawData};
use primus_distr::{DiscreteGaussian, SignedDiscreteGaussian};
use primus_integer::{FheUint, UnsignedInteger};
use primus_reduce::ReduceAddAssign;
use rand::distr::{Distribution, Uniform};

use super::CrtPolynomial;

impl<T: FheUint> CrtPolynomial<Vec<T>> {
    /// Generate a random binary [`CrtPolynomial<Vec<T>, T>`].
    #[inline]
    pub fn random_binary<R>(poly_length: usize, moduli_count: usize, rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(primus_distr::sample_crt_binary_values(
            poly_length,
            moduli_count,
            rng,
        ))
    }

    /// Generate a random ternary [`CrtPolynomial<Vec<T>, T>`].
    #[inline]
    pub fn random_ternary<R>(poly_length: usize, moduli_minus_one: &[T], rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(primus_distr::sample_crt_ternary_values(
            poly_length,
            moduli_minus_one,
            rng,
        ))
    }

    /// Generate a random uniform [`CrtPolynomial<Vec<T>, T>`].
    #[inline]
    pub fn random_uniform<R>(poly_length: usize, uniform_distrs: &[Uniform<T>], rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(primus_distr::sample_crt_uniform_values(
            poly_length,
            uniform_distrs,
            rng,
        ))
    }

    /// Generate a random gaussian [`CrtPolynomial<Vec<T>, T>`].
    #[inline]
    pub fn random_gaussian<R>(
        poly_length: usize,
        moduli_value: &[T],
        gaussian: &SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(primus_distr::sample_crt_gaussian_values(
            poly_length,
            moduli_value,
            gaussian,
            rng,
        ))
    }
}

impl<S, T> CrtPolynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Fill with random binary values.
    #[inline]
    pub fn random_binary_assign<R>(&mut self, poly_length: usize, rng: &mut R)
    where
        R: rand::Rng + rand::CryptoRng,
    {
        primus_distr::sample_crt_binary_values_to(self.as_mut_slice(), poly_length, rng)
    }

    /// Fill with random ternary values.
    #[inline]
    pub fn random_ternary_assign<R>(
        &mut self,
        poly_length: usize,
        moduli_minus_one: &[T],
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        primus_distr::sample_crt_ternary_values_to(
            self.as_mut_slice(),
            poly_length,
            moduli_minus_one,
            rng,
        )
    }

    /// Fill with random uniform values.
    #[inline]
    pub fn random_uniform_assign<R>(
        &mut self,
        poly_length: usize,
        uniform_distrs: &[Uniform<T>],
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        primus_distr::sample_crt_uniform_values_to(
            self.as_mut_slice(),
            poly_length,
            uniform_distrs,
            rng,
        )
    }

    /// Fill with random discrete gaussian values.
    #[inline]
    pub fn random_gaussian_assign<R>(
        &mut self,
        poly_length: usize,
        moduli_value: &[T],
        gaussian: &SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        primus_distr::sample_crt_gaussian_values_to(
            self.as_mut_slice(),
            poly_length,
            moduli_value,
            gaussian,
            rng,
        )
    }

    /// Adds discrete gaussian noise to each coefficient.
    #[inline]
    pub fn add_random_gaussian_assign<R, M>(
        &mut self,
        poly_length: usize,
        gaussian: &DiscreteGaussian<T>,
        moduli: &[M],
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: Copy + ReduceAddAssign<T>,
    {
        self.iter_each_modulus_mut(poly_length)
            .zip(moduli)
            .for_each(|(poly, &modulus)| {
                let rng = &mut *rng;
                poly.iter_mut()
                    .zip(gaussian.sample_iter(rng))
                    .for_each(|(a, b)| modulus.reduce_add_assign(a, b));
            });
    }
}
