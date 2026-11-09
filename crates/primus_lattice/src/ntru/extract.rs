//! Sample extraction from the NTRU phase `f * c`.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_reduce::RingContext;

use super::Ntru;
use crate::lwe::Lwe;

impl<S, T> Ntru<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Extracts the constant-term NTRU phase as an LWE ciphertext.
    ///
    /// For an NTRU ciphertext `c` encrypted under `f`, this writes
    /// `a[0] = -c[0]`, `a[i] = c[N - i]` for `i > 0`, and `b = 0`. Hence the
    /// LWE phase `b - <a, f>` equals the constant coefficient of `f * c` in
    /// `Z_q[X] / (X^N + 1)`.
    ///
    /// # Correctness
    ///
    /// `output` must have LWE dimension `N`.
    ///
    /// Input is one nonempty coefficient polynomial of length `N`, with
    /// canonical values under `modulus`. Extraction uses the coefficient
    /// vector of the NTRU secret `f` as the LWE key; output is overwritten.
    ///
    /// # Panics
    ///
    /// Panics if the NTRU polynomial is empty.
    #[inline]
    pub fn extract_lwe_to<M, A>(&self, output: &mut Lwe<A>, modulus: M)
    where
        M: RingContext<T>,
        A: DataMut<Elem = T>,
    {
        self.extract_lwe_at_to(0, output, modulus);
    }

    /// Extracts coefficient `index` of the NTRU phase into an LWE buffer.
    ///
    /// For `c` encrypted under `f`, writes `b = 0` and a mask such that
    /// `b - <a, f>` equals coefficient `index` of `f*c` modulo `X^N + 1`.
    /// Canonical input residues produce canonical output without allocation.
    /// `output` must have LWE dimension `N`.
    ///
    /// # Correctness
    ///
    /// Input is one nonempty coefficient polynomial of length `N`, with
    /// canonical values under `modulus`. Extraction uses the coefficient
    /// vector of the NTRU secret `f` as the LWE key; output is overwritten.
    ///
    /// # Panics
    ///
    /// Panics unless `index < N`.
    #[inline]
    pub fn extract_lwe_at_to<M, A>(&self, index: usize, output: &mut Lwe<A>, modulus: M)
    where
        M: RingContext<T>,
        A: DataMut<Elem = T>,
    {
        let coefficients = self.as_ref();
        assert!(
            index < coefficients.len(),
            "NTRU extraction index is out of range"
        );
        debug_assert_eq!(
            output.dimension(),
            coefficients.len(),
            "LWE output dimension must equal N"
        );
        let (a, b) = output.a_b_mut();
        *b = T::ZERO;
        // Terms with secret index <= index do not wrap in f*c, so their
        // mask entries are negated for b-<a,f>. Wrapped terms have positive masks.
        let (negative, wrapped) = a.split_at_mut(index + 1);
        for (output, &input) in negative.iter_mut().zip(coefficients[..=index].iter().rev()) {
            *output = modulus.reduce_neg(input);
        }
        for (output, &input) in wrapped.iter_mut().zip(coefficients.iter().rev()) {
            *output = input;
        }
    }
}
