use primus_data::Data;
use primus_integer::FheUint;
use primus_lattice::lwe::MultiMsgLwe;
use primus_reduce::RingContext;
use rand::distr::Distribution;

use crate::{LweEncryptionParameters, MultiMsgLweCiphertext};

use super::LweSecretKey;

impl<T: FheUint> LweSecretKey<T> {
    /// Allocates one shared mask and encrypts each already encoded body.
    ///
    /// Stores `n + plaintexts.len()` coefficients, with at most `n` bodies.
    /// Body `i` uses the mask rotated right by `i`, negating its first `i` values.
    /// Even an empty plaintext slice samples and retains the shared mask.
    ///
    /// # Correctness
    ///
    /// The key must satisfy the [type's parameter contract](Self#correctness).
    /// Plaintexts must be canonical under the parameter modulus; no codec is used.
    ///
    /// # Panics
    ///
    /// Panics before sampling on a recorded modulus mismatch, excessive body
    /// count or storage length overflow. Debug builds check parameter dimension.
    #[must_use]
    pub fn encrypt_encoded_packed<M, R>(
        &self,
        plaintexts: &[T],
        params: &LweEncryptionParameters<T, M>,
        rng: &mut R,
    ) -> MultiMsgLweCiphertext<T>
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_modulus(params.cipher_modulus());
        debug_assert_eq!(self.dimension(), params.dimension().get());
        let mut output = allocate_packed(params.dimension().get(), plaintexts.len());
        output
            .a_b_mut(params.dimension().get())
            .1
            .copy_from_slice(plaintexts);
        self.encrypt_packed_bodies_assign(&mut output, params, rng);
        output
    }

    /// Samples the shared mask and adds each rotated mask product and noise to
    /// the encoded bodies. The caller supplies exactly `n + count` coefficients,
    /// with `count <= n`, canonical bodies, and a key matching the parameters.
    #[inline]
    pub(super) fn encrypt_packed_bodies_assign<R, M>(
        &self,
        output: &mut MultiMsgLweCiphertext<T>,
        params: &LweEncryptionParameters<T, M>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        let dimension = params.dimension().get();
        let modulus = params.cipher_modulus();
        let (mask, bodies) = output.a_b_mut(dimension);
        mask.iter_mut()
            .zip(params.cipher_modulus_uniform_distr().sample_iter(&mut *rng))
            .for_each(|(out, sample)| *out = sample);
        for (index, body) in bodies.iter_mut().enumerate() {
            let product = self.rotated_mask_product(mask, index, dimension, modulus);
            modulus.reduce_add_assign(body, product);
        }
        // Keep RNG state out of the rotated dot-product loop.
        for (body, error) in bodies
            .iter_mut()
            .zip(params.noise_distribution().sample_iter(rng))
        {
            modulus.reduce_add_assign(body, error);
        }
    }

    /// Allocates the canonical phases of a packed ciphertext, without decoding.
    ///
    /// Returns one phase per body, or an empty vector if only the mask is retained.
    ///
    /// # Correctness
    ///
    /// Input coefficients must be canonical under `modulus`, using the rotated
    /// mask layout of [`Self::encrypt_encoded_packed`]. The key's coefficient
    /// contract applies to both contiguous dot products in each rotation.
    ///
    /// # Panics
    ///
    /// Panics if the recorded modulus differs, storage is shorter than the key
    /// dimension, or the number of bodies exceeds that dimension.
    #[must_use]
    pub fn decrypt_phase_packed<M: RingContext<T>>(
        &self,
        input: &MultiMsgLwe<impl Data<Elem = T>>,
        modulus: M,
    ) -> Vec<T> {
        self.check_modulus(modulus);
        let dimension = self.dimension();
        let (mask, bodies) = input.a_b(dimension);
        assert!(
            bodies.len() <= dimension,
            "packed LWE message count must not exceed the LWE dimension"
        );
        bodies
            .iter()
            .enumerate()
            .map(|(index, &body)| {
                modulus.reduce_sub(
                    body,
                    self.rotated_mask_product(mask, index, dimension, modulus),
                )
            })
            .collect()
    }

    /// Computes the phase mask product for body `index`; `index < dimension`
    /// and both the mask and key have exactly `dimension` canonical coefficients.
    /// Negating the wrapped prefix implements the negacyclic extraction layout.
    #[inline]
    fn rotated_mask_product<M>(&self, a: &[T], index: usize, dimension: usize, modulus: M) -> T
    where
        M: RingContext<T>,
    {
        if index == 0 {
            modulus.reduce_dot_product(a, self.as_ref())
        } else {
            let (mask_prefix, mask_suffix) = a.split_at(dimension - index);
            let (key_prefix, key_suffix) = self.as_ref().split_at(index);
            // <(-suffix, prefix), s> = <prefix, s[index..]> - <suffix, s[..index]>.
            // Two contiguous dot products retain the backend's slice/SIMD kernels.
            modulus.reduce_sub(
                modulus.reduce_dot_product(mask_prefix, key_suffix),
                modulus.reduce_dot_product(mask_suffix, key_prefix),
            )
        }
    }
}

/// Allocates the packed mask/body layout, enforcing its independent-mask limit.
#[inline]
pub(super) fn allocate_packed<T: FheUint>(
    dimension: usize,
    count: usize,
) -> MultiMsgLweCiphertext<T> {
    // Beyond n bodies the negacyclic mask repeats up to sign, exposing message
    // sums or differences. Reject this before allocating or sampling output.
    assert!(
        count <= dimension,
        "packed LWE message count must not exceed the LWE dimension"
    );
    let length = dimension
        .checked_add(count)
        .expect("packed LWE storage length overflow");
    MultiMsgLweCiphertext::new(vec![T::ZERO; length])
}
