//! Square-matrix LWE public-key encryption.

mod batch;
mod message;

use primus_data::DataMut;
use primus_distr::{DiscreteGaussian, sample_sparse_ternary_values_to};
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lattice::lwe::Lwe;
use primus_reduce::RingContext;
use rand::distr::Uniform;

use crate::{LweCiphertext, LweSecretKeyRef};

// A full row block consumes whole random words for any ciphertext tile count.
const ROWS_PER_BLOCK: usize = 16;

/// A Lindner–Peikert-style public key `(A, b = A s + e)` with square `A`.
///
/// Stores `n` contiguous rows `[A_i, b_i]`, each an LWE encryption of zero
/// under the same `n`-dimensional secret. Encryption samples independent
/// ephemeral coefficients with `Pr[r_i = 0] = 1/2` and
/// `Pr[r_i = -1] = Pr[r_i = 1] = 1/4`, and fresh Gaussian errors `e1, e2`:
///
/// ```text
/// a = A^T r + e1
/// c = b^T r + e2 + Encode(message)
/// ```
///
/// The ciphertext `[a, c]` uses the existing LWE layout and secret-key decoder.
/// This is a CPA encryption primitive, not a KEM or a CCA transform.
/// The square-matrix construction follows
/// [Lindner and Peikert](https://eprint.iacr.org/2010/613), with the ephemeral
/// distribution fixed to the sparse ternary law above.
/// Encryption packs sixteen ephemeral coefficients per random word. Unused
/// bits are discarded after each ciphertext or batch tile; seeded ciphertext
/// bytes are not guaranteed to remain identical across library versions.
///
/// # Correctness
///
/// Decryption requires `e^T r + e2 - e1^T s` to stay within the plaintext
/// codec's decoding margin. Small centered secret coefficients are needed to
/// control `e1^T s`. The high-level methods use `params.noise_distribution()`
/// for both `e1` and `e2`; generation uses its supplied sampler for `e`.
/// None of these samplers specifies the *total* output noise distribution.
///
/// Parameters must jointly ensure LWE security for the long-term secret and
/// the ephemeral sparse ternary secret, and the desired decryption failure
/// probability. This type validates dimensions and modulus identity, not these
/// security or noise bounds. Existing secret-key parameters are not necessarily
/// suitable public-key parameters.
#[derive(Clone)]
pub struct LwePublicKey<T: FheUint> {
    data: Vec<T>,
    dimension: LweDimension,
    modulus_minus_one: T,
}

impl<T: FheUint> LwePublicKey<T> {
    /// Generates `n` independent zero encryptions under `secret_key`.
    ///
    /// Borrows encoded or signed coefficients and an already prepared noise
    /// sampler. Only the dimension and modulus identity are retained; generation
    /// does not prepare or clone sampling tables. No message codec is needed.
    ///
    /// # Correctness
    ///
    /// The secret must satisfy [`LweSecretKeyRef`]'s coefficient-range contract
    /// under `modulus`. The raw view has no recorded modulus; when
    /// borrowing an owning key, check its modulus before calling `as_view()`.
    /// `uniform` must sample canonical residues uniformly under the same modulus.
    /// The [type's security and noise requirements](Self#correctness) apply.
    ///
    /// # Panics
    ///
    /// Panics before sampling if the secret dimension differs from the nonzero
    /// supplied dimension, the noise sampler has a different modulus, or the
    /// public-key storage length overflows `usize`.
    #[must_use]
    #[inline]
    pub fn generate<M, R>(
        secret_key: LweSecretKeyRef<'_, T>,
        dimension: LweDimension,
        modulus: M,
        uniform: Uniform<T>,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) -> Self
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        assert_eq!(
            secret_key.dimension(),
            dimension.get(),
            "LWE public-key dimension mismatch"
        );
        assert_eq!(
            noise.modulus_minus_one(),
            modulus.minus_one(),
            "LWE public-key noise modulus mismatch"
        );
        let row_len = dimension.ciphertext_len();
        let length = dimension
            .get()
            .checked_mul(row_len)
            .expect("LWE public-key storage length overflow");
        let mut data = vec![T::ZERO; length];
        for row in data.chunks_exact_mut(row_len) {
            secret_key.encrypt_encoded_to(
                T::ZERO,
                &mut Lwe::new(row),
                modulus,
                uniform,
                noise,
                rng,
            );
        }
        Self {
            data,
            dimension,
            modulus_minus_one: modulus.minus_one(),
        }
    }

    /// Returns the dimension of the secret and output LWE ciphertexts.
    #[must_use]
    #[inline]
    pub fn dimension(&self) -> LweDimension {
        self.dimension
    }

    /// Returns `q - 1`, including `T::MAX` for the native modulus.
    #[must_use]
    #[inline]
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.modulus_minus_one
    }

    /// Returns `n` row-major `[A_i, b_i]` blocks of `n + 1` canonical residues.
    #[must_use]
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Encrypts a canonical encoded residue in a newly allocated ciphertext.
    ///
    /// Zero produces a randomized encryption of zero. The correctness and
    /// panic conditions of [`Self::encrypt_encoded_to`] apply, except that the
    /// output length is supplied by this key.
    #[must_use]
    pub fn encrypt_encoded<M, R>(
        &self,
        plaintext: T,
        modulus: M,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) -> LweCiphertext<T>
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_modulus(modulus);
        let mut output = LweCiphertext::zero(self.dimension.get());
        self.encrypt_encoded_slice(plaintext, output.as_mut(), modulus, noise, rng);
        output
    }

    /// Overwrites `output` with an encryption of an already encoded residue.
    ///
    /// Samples fresh `e1, e2` from `noise`, then streams ephemeral coefficients
    /// while accumulating public-key rows. No allocation or scratch is needed.
    /// Encryption branches on ephemeral coefficients and skips zero rows;
    /// this is not a constant-time implementation.
    ///
    /// # Correctness
    ///
    /// `plaintext` must be in `[0,q)`, and `noise` must encode its samples under
    /// `modulus`. These conditions are not checked. The
    /// [type's security and noise requirements](Self#correctness) also apply.
    ///
    /// # Panics
    ///
    /// Panics before writing or sampling if the modulus differs from the key's
    /// or `output` does not have exactly `self.dimension() + 1` coefficients.
    /// A panicking RNG can leave partially written output.
    pub fn encrypt_encoded_to<M, R>(
        &self,
        plaintext: T,
        output: &mut Lwe<impl DataMut<Elem = T>>,
        modulus: M,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_modulus(modulus);
        let output = output.as_mut();
        assert_eq!(
            output.len(),
            self.dimension.ciphertext_len(),
            "LWE public-key output length mismatch"
        );
        self.encrypt_encoded_slice(plaintext, output, modulus, noise, rng);
    }

    #[inline]
    fn check_modulus<M: RingContext<T>>(&self, modulus: M) {
        assert_eq!(
            modulus.minus_one(),
            self.modulus_minus_one,
            "LWE public-key modulus mismatch"
        );
    }

    /// Overwrites a validated `n + 1` output slice under the key's modulus.
    /// Interleaved bodies let one slice kernel accumulate both `A^T r` and
    /// `b^T r`, without a transpose, temporary secret vector, or extra pass.
    /// Ternary coefficients select addition, subtraction, or no work once per
    /// row, outside the slice kernel's coefficient loop. Gaussian errors are
    /// sampled first, then packed ternary coefficients in matrix-row order.
    fn encrypt_encoded_slice<M, R>(
        &self,
        plaintext: T,
        output: &mut [T],
        modulus: M,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        noise.sample_to(output, rng);
        modulus.reduce_add_assign(&mut output[self.dimension.get()], plaintext);
        let row_len = self.dimension.ciphertext_len();
        // Clamping keeps the block length within the validated key allocation.
        let block_len = self.dimension.get().min(ROWS_PER_BLOCK) * row_len;
        let mut ephemeral = [0i8; ROWS_PER_BLOCK];
        for rows in self.data.chunks(block_len) {
            let coefficients = &mut ephemeral[..rows.len() / row_len];
            sample_sparse_ternary_values_to(coefficients, -1, rng);
            for (row, &coefficient) in rows.chunks_exact(row_len).zip(coefficients.iter()) {
                match coefficient {
                    1 => modulus.reduce_add_slice_assign(output, row),
                    -1 => modulus.reduce_sub_slice_assign(output, row),
                    _ => {}
                }
            }
        }
    }
}
