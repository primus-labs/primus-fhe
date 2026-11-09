//! NTT GLWE encryption.

use super::NttGlweSecretKey;
use crate::{GlweEncryptionParameters, NttGlweCiphertext};
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_reduce::FieldContext;

impl<T: FheUint> NttGlweSecretKey<T> {
    /// Encrypts a polynomial whose coefficients are already encoded in
    /// `[0, q)`. No plaintext codec is needed; the key supplies the layout.
    ///
    /// # Correctness
    ///
    /// Input coefficients must be canonical residues modulo the ciphertext modulus.
    /// Use [`Self::decrypt_phase_to`] to recover the noisy encoded polynomial.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes if the input/output lengths disagree with
    /// the key layout, or the key, parameter and table moduli or table length differ.
    pub fn encrypt_encoded_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttGlweCiphertext<B>,
        params: &GlweEncryptionParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_encrypt_compatible(output.as_ref().len(), params, ntt_table);
        assert_eq!(
            input.as_ref().len(),
            self.poly_length().get(),
            "GLWE message length mismatch"
        );
        self.encrypt_encoded_kernel_to(
            input.as_view(),
            output.as_mut_view(),
            params,
            ntt_table,
            rng,
        );
    }

    /// Encrypts zeros (randomized encryption of zero).
    ///
    /// # Panics
    ///
    /// Inherits the resource checks of [`Self::encrypt_zeros_to`].
    #[must_use]
    pub fn encrypt_zeros<M, Table, R>(
        &self,
        params: &GlweEncryptionParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> NttGlweCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut output: NttGlweCiphertext<Vec<T>> = NttGlweCiphertext::zero(self.size.glwe_len());
        self.encrypt_zeros_to(&mut output, params, ntt_table, rng);
        output
    }

    /// Encrypts zero into the existing ciphertext output.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes if the output length disagrees with the
    /// key layout, or the key, parameter and table moduli or table length differ.
    pub fn encrypt_zeros_to<M, Table, R, A>(
        &self,
        output: &mut NttGlweCiphertext<A>,
        params: &GlweEncryptionParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: DataMut<Elem = T>,
    {
        self.assert_encrypt_compatible(output.as_ref().len(), params, ntt_table);
        self.encrypt_zeros_kernel_to(output.as_mut_view(), params, ntt_table, rng);
    }

    /// Encrypts an encoded coefficient polynomial without repeating boundary checks.
    ///
    /// The caller must validate key/output layouts and matching parameter/transform
    /// domains before entering this kernel.
    /// Input length must equal the key's polynomial length; coefficients must be
    /// canonical in the ciphertext ring. No plaintext or gadget scaling is applied.
    #[inline]
    pub(super) fn encrypt_encoded_kernel_to<M, Table, R>(
        &self,
        input: Polynomial<&[T]>,
        output: NttGlweCiphertext<&mut [T]>,
        params: &GlweEncryptionParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.encrypt_kernel_to(output, params, ntt_table, rng, |body| {
            Polynomial::new(body).add_assign(&input, params.cipher_modulus());
        });
    }

    /// Encrypts zero without repeating boundary checks.
    ///
    /// The caller must validate key/output layouts and matching parameter/transform
    /// domains before entering this kernel.
    #[inline]
    pub(super) fn encrypt_zeros_kernel_to<M, Table, R>(
        &self,
        output: NttGlweCiphertext<&mut [T]>,
        params: &GlweEncryptionParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.encrypt_kernel_to(output, params, ntt_table, rng, |_| {});
    }

    /// Validates layout and transform compatibility before sampling or writing output.
    #[inline]
    pub(super) fn assert_encrypt_compatible<M, Table>(
        &self,
        output_len: usize,
        params: &GlweEncryptionParameters<T, M>,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        self.assert_ntt_compatible(params.cipher_modulus(), ntt_table);
        assert_eq!(
            output_len,
            self.size.glwe_len(),
            "GLWE output layout mismatch"
        );
    }

    /// Encrypts with validated layouts and matching parameter/transform domains.
    /// Calls `add_message` once on the sampled coefficient noise, before transforming
    /// the body. Its concrete closure type specializes plaintext/encoded/zero paths
    /// without dynamic dispatch or an intermediate message buffer.
    pub(super) fn encrypt_kernel_to<M, Table, R>(
        &self,
        mut output: NttGlweCiphertext<&mut [T]>,
        params: &GlweEncryptionParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
        add_message: impl FnOnce(&mut [T]),
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let poly_length = self.size.poly_length().get();
        debug_assert_eq!(ntt_table.poly_length().get(), poly_length);
        debug_assert_eq!(output.as_ref().len(), self.size.glwe_len());

        let modulus = params.cipher_modulus();
        let (a, mut b) = output.a_b_mut(poly_length);

        // Sample noise into b
        primus_distr::sample_gaussian_values_to(b.as_mut(), params.noise_distribution(), rng);

        add_message(b.as_mut());
        ntt_table.transform_slice(b.as_mut());

        // Sample each a_i, then accumulate a_i * s_i into b pointwise.
        let uniform_distribution = params.cipher_modulus_uniform_distr();
        for (si, mut ai) in self.iter().zip(a) {
            primus_distr::sample_uniform_values_to(ai.as_mut(), &uniform_distribution, rng);
            b.add_mul_assign(&ai, &si, modulus);
        }
    }
}
