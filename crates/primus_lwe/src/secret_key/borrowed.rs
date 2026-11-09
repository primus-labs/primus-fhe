use primus_data::{Data, DataMut};
use primus_distr::DiscreteGaussian;
use primus_integer::FheUint;
use primus_lattice::lwe::Lwe;
use primus_reduce::RingContext;
use rand::distr::{Distribution, Uniform};

use crate::LweCiphertext;

/// Borrowed LWE secret coefficients, without copying or converting key storage.
///
/// Obtain an encoded view with [`LweSecretKey::as_view`](super::LweSecretKey::as_view),
/// or borrow signed ring-secret coefficients directly with [`Self::Signed`].
/// This view performs raw arithmetic; it owns neither the key nor a plaintext codec
/// and carries no modulus metadata. It is not a validated key binding: when
/// borrowing an owning encoded key, check its recorded modulus before conversion.
///
/// # Correctness
///
/// Encoded coefficients must be canonical residues under the supplied modulus.
/// Signed coefficients must have magnitude strictly less than an explicit `q`;
/// every signed value is valid for the native modulus. These ranges are not
/// checked in release builds. Operations preserve canonical ciphertext residues.
#[derive(Clone, Copy)]
pub enum LweSecretKeyRef<'a, T: FheUint> {
    /// Secret coefficients already encoded in the ciphertext modulus.
    Encoded(&'a [T]),
    /// Signed ring-secret coefficients viewed as an LWE key.
    Signed(&'a [T::SignedInteger]),
}

impl<T: FheUint> LweSecretKeyRef<'_, T> {
    /// Returns the LWE dimension.
    #[must_use]
    #[inline]
    pub fn dimension(self) -> usize {
        match self {
            Self::Encoded(coefficients) => coefficients.len(),
            Self::Signed(coefficients) => coefficients.len(),
        }
    }

    /// Encrypts an already encoded plaintext in a newly allocated ciphertext.
    ///
    /// Passing zero encrypts zero; no plaintext codec or scaling is applied.
    /// The correctness conditions of [`Self::encrypt_encoded_to`] apply.
    ///
    /// # Panics
    ///
    /// Panics if the ciphertext length overflows `usize`.
    #[must_use]
    #[inline]
    pub fn encrypt_encoded<M, R>(
        self,
        plaintext: T,
        modulus: M,
        uniform: Uniform<T>,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) -> LweCiphertext<T>
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let dimension = self.dimension();
        let length = dimension.checked_add(1).expect("LWE length overflow");
        // Reserve the body as well, and initialize each mask coefficient once.
        let mut data = Vec::<T>::with_capacity(length);
        data.spare_capacity_mut()[..dimension]
            .iter_mut()
            .zip(uniform.sample_iter(&mut *rng))
            .for_each(|(out, sample)| {
                out.write(sample);
            });
        // SAFETY: Capacity is at least dimension + 1. The unbounded sampler
        // initialized every element in the dimension-long slice above. A
        // panicking sampler leaves length zero, so no unwritten value is read.
        unsafe { data.set_len(dimension) };
        let error = noise.sample(rng);
        let body = modulus.reduce_add(self.dot_product(&data, modulus), error);
        data.push(modulus.reduce_add(body, plaintext));
        Lwe::new(data)
    }

    /// Overwrites an existing ciphertext with an encryption of an encoded value.
    ///
    /// Samples the mask and noise, then writes `b = <a,s> + noise + plaintext`
    /// modulo `q`. All coefficients are overwritten; no allocation is performed.
    /// Passing zero produces a randomized encryption of zero.
    ///
    /// # Correctness
    ///
    /// `plaintext` and encoded key coefficients must be in `[0,q)`; signed keys
    /// follow the [type contract](Self#correctness). `uniform` must sample masks
    /// uniformly under `modulus`, and `noise` must encode its signed samples under
    /// the same modulus. Ranges and distribution compatibility are not checked.
    ///
    /// # Panics
    ///
    /// Panics before writing if `output` lacks a body or its dimension differs
    /// from this key. A panicking RNG can leave partially written output.
    #[inline]
    pub fn encrypt_encoded_to<M, R>(
        self,
        plaintext: T,
        output: &mut Lwe<impl DataMut<Elem = T>>,
        modulus: M,
        uniform: Uniform<T>,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let (body, mask) = output
            .as_mut()
            .split_last_mut()
            .expect("LWE output must contain a body");
        assert_eq!(
            mask.len(),
            self.dimension(),
            "LWE output dimension must match the secret key"
        );
        mask.iter_mut()
            .zip(uniform.sample_iter(&mut *rng))
            .for_each(|(out, sample)| *out = sample);
        let error = noise.sample(rng);
        *body = modulus.reduce_add(self.dot_product(mask, modulus), error);
        modulus.reduce_add_assign(body, plaintext);
    }

    /// Returns the canonical noisy phase `b - <a,s>` without decoding it.
    ///
    /// This can be passed to a plaintext codec or compared with the encoding of
    /// an independently known message when measuring decryption failures.
    ///
    /// # Correctness
    ///
    /// `input` must be canonical under `modulus`, and the key must satisfy the
    /// [type contract](Self#correctness) for that same modulus.
    ///
    /// # Panics
    ///
    /// Panics if `input` lacks a body or its dimension differs from this key.
    #[must_use]
    #[inline]
    pub fn decrypt_phase<M>(self, input: &Lwe<impl Data<Elem = T>>, modulus: M) -> T
    where
        M: RingContext<T>,
    {
        let (body, mask) = input
            .as_ref()
            .split_last()
            .expect("LWE input must contain a body");
        modulus.reduce_sub(*body, self.dot_product(mask, modulus))
    }

    /// Selects the key representation once; the modulus backend owns encoding
    /// and scalar/SIMD dot-product dispatch.
    #[inline]
    fn dot_product<M>(self, mask: &[T], modulus: M) -> T
    where
        M: RingContext<T>,
    {
        match self {
            Self::Encoded(key) => modulus.reduce_dot_product(mask, key),
            Self::Signed(key) => modulus.reduce_dot_product_signed(mask, key),
        }
    }
}
