use primus_data::{DataMut, RawData};
use primus_integer::FheUint;
use rand::distr::Uniform;

use super::DcrtPolynomial;

impl<T: FheUint> DcrtPolynomial<Vec<T>> {
    /// Generate a random uniform [`DcrtPolynomial<Vec<T>, T>`].
    #[inline]
    pub fn random_uniform<R>(length: usize, uniform_distrs: &[Uniform<T>], rng: &mut R) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
    {
        Self(primus_distr::sample_crt_uniform_values(
            length,
            uniform_distrs,
            rng,
        ))
    }
}

impl<S, T> DcrtPolynomial<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Fill with random uniform values.
    #[inline]
    pub fn random_uniform_assign<R>(
        &mut self,
        length: usize,
        uniform_distrs: &[Uniform<T>],
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        primus_distr::sample_crt_uniform_values_to(self.as_mut_slice(), length, uniform_distrs, rng)
    }
}
