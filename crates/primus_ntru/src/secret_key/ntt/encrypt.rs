//! Codec-free encoded and zero encryption.

use super::NttNtruSecretKey;
use crate::{NtruEncryptionParameters, NttNtruCiphertext};
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

impl<T: FheUint> NttNtruSecretKey<T> {
    /// Encrypts coefficients already encoded modulo `q` into `output`.
    ///
    /// # Correctness
    ///
    /// Every input coefficient must be a canonical residue in `[0, q)`;
    /// this entry point does not scale or reduce the encoded message.
    /// Use the key's construction-time NTT roots and evaluation order.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes if key/parameter/table/input/output
    /// lengths or moduli disagree.
    pub fn encrypt_encoded_to<M, Table, R, A, B>(
        &self,
        encoded: &Polynomial<A>,
        output: &mut NttNtruCiphertext<B>,
        params: &NtruEncryptionParameters<T, M>,
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
            encoded.as_ref().len(),
            self.poly_length(),
            "NTRU encoded input length mismatch"
        );
        self.encrypt_encoded_to_unchecked(
            encoded.as_view(),
            output.as_mut_view(),
            params,
            ntt_table,
            rng,
        );
    }

    /// Encrypts zero into a freshly allocated NTT ciphertext.
    /// Inherits [`Self::encrypt_zeros_to`]'s transform and layout requirements.
    #[must_use]
    pub fn encrypt_zeros<M, Table, R>(
        &self,
        params: &NtruEncryptionParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> NttNtruCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut output = NttNtruCiphertext::zero(self.poly_length());
        self.encrypt_zeros_to(&mut output, params, ntt_table, rng);
        output
    }

    /// Encrypts canonical coefficients after the ordinary or gadget boundary validates
    /// complete operands and backend resources. No codec or gadget scaling is applied here.
    pub(super) fn encrypt_encoded_to_unchecked<M, Table, R>(
        &self,
        encoded: Polynomial<&[T]>,
        output: NttNtruCiphertext<&mut [T]>,
        params: &NtruEncryptionParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        debug_assert_eq!(encoded.as_ref().len(), self.poly_length());
        debug_assert_eq!(output.as_ref().len(), self.poly_length());
        self.encrypt_kernel_to(output, params, ntt_table, rng, |coefficients| {
            Polynomial(coefficients).add_assign(&encoded, params.cipher_modulus());
        });
    }

    /// Encrypts the zero polynomial into the existing output without allocating.
    ///
    /// # Correctness
    ///
    /// Use the key's construction-time NTT roots and evaluation order.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes if key/parameter/table/output lengths
    /// or moduli disagree.
    pub fn encrypt_zeros_to<M, Table, R, B>(
        &self,
        output: &mut NttNtruCiphertext<B>,
        params: &NtruEncryptionParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = T>,
    {
        self.assert_encrypt_compatible(output.as_ref().len(), params, ntt_table);
        self.encrypt_zeros_to_unchecked(output.as_mut_view(), params, ntt_table, rng);
    }

    /// Encrypts zero after the ordinary or gadget boundary validates output and resources.
    pub(super) fn encrypt_zeros_to_unchecked<M, Table, R>(
        &self,
        output: NttNtruCiphertext<&mut [T]>,
        params: &NtruEncryptionParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        debug_assert_eq!(output.as_ref().len(), self.poly_length());
        self.encrypt_kernel_to(output, params, ntt_table, rng, |_| {});
    }

    /// Validates ordinary output and backend resources before sampling or writes.
    pub(super) fn assert_encrypt_compatible<M, Table>(
        &self,
        output_len: usize,
        params: &NtruEncryptionParameters<T, M>,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        self.assert_domain(params, ntt_table);
        assert_eq!(
            output_len,
            self.poly_length(),
            "NTRU output length mismatch"
        );
    }

    /// Requires the public or gadget boundary to validate complete operands and resources.
    /// Sample noise, inject the message, then transform and multiply by the inverse secret;
    /// the callback runs once on coefficient noise without an intermediate encoded buffer.
    /// Message validation stays in the adapter, so codec failures keep their sampling order.
    pub(super) fn encrypt_kernel_to<M, Table, R>(
        &self,
        mut output: NttNtruCiphertext<&mut [T]>,
        params: &NtruEncryptionParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
        add_message: impl FnOnce(&mut [T]),
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let coefficients = output.as_mut();
        primus_distr::sample_gaussian_values_to(coefficients, params.noise_distribution(), rng);
        add_message(coefficients);

        ntt_table.transform_slice(coefficients);
        NttPolynomial(coefficients).mul_assign(&self.inv_key, params.cipher_modulus());
    }
}
