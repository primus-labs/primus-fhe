//! NTT public-key encryption.

use super::{NttGlwePublicEncryptWorkspace, NttGlwePublicKey};
use crate::{GlweEncryptionParameters, NttGlweCiphertext};
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;
use primus_shape::PolyLength;

impl<S, T> NttGlwePublicKey<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Encrypts an already encoded coefficient polynomial without plaintext scaling.
    /// The table defines N; the public key contains k mask polynomials and a body.
    /// No plaintext codec or separate parameter layout is needed.
    ///
    /// # Correctness
    ///
    /// Input coefficients must be canonical residues modulo the ciphertext modulus.
    /// Use [`crate::NttGlweSecretKey::decrypt_phase_to`] to recover encoded coefficients with noise;
    /// ordinary decryption also applies plaintext decoding.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes if the key is not a sequence of at least
    /// two complete polynomials, the output length differs from the key, input/workspace lengths
    /// differ from N, or the parameter and table moduli differ.
    pub fn encrypt_encoded_to<M, Table, R, A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut NttGlweCiphertext<B>,
        params: &GlweEncryptionParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_raw_key_layout(ntt.poly_length());
        assert_eq!(
            input.as_ref().len(),
            ntt.poly_length().get(),
            "GLWE message length mismatch"
        );
        NttGlwePublicKey::from(self.key.as_view()).encrypt_encoded_kernel_to(
            input.as_view(),
            output.as_mut_view(),
            params,
            ntt,
            rng,
            workspace,
        );
    }

    /// Encrypts zero into `output`.
    ///
    /// # Panics
    ///
    /// Inherits [`Self::encrypt_encoded_to`]'s resource checks, without an input
    /// polynomial length check.
    pub fn encrypt_zeros_to<M, Table, R, B>(
        &self,
        output: &mut NttGlweCiphertext<B>,
        params: &GlweEncryptionParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = T>,
    {
        self.assert_raw_key_layout(ntt.poly_length());
        NttGlwePublicKey::from(self.key.as_view()).encrypt_zeros_kernel_to(
            output.as_mut_view(),
            params,
            ntt,
            rng,
            workspace,
        );
    }

    /// Encrypts zero into a newly allocated NTT-domain ciphertext.
    ///
    /// # Panics
    ///
    /// Inherits [`Self::encrypt_zeros_to`]'s resource checks.
    #[must_use]
    pub fn encrypt_zeros<M, Table, R>(
        &self,
        params: &GlweEncryptionParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
    ) -> NttGlweCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut output = NttGlweCiphertext::zero(self.key.as_ref().len());
        self.encrypt_zeros_to(&mut output, params, ntt, rng, workspace);
        output
    }

    /// Raw public-key storage has no layout metadata. Establish complete mask/body
    /// polynomials here; message APIs instead check the supplied ordinary layout.
    #[inline]
    fn assert_raw_key_layout(&self, poly_length: PolyLength) {
        let n = poly_length.get();
        let len = self.key.as_ref().len();
        assert!(
            len >= 2 * n && len & (n - 1) == 0,
            "GLWE public key must contain complete mask and body polynomials"
        );
    }
}

impl<T: FheUint> NttGlwePublicKey<&[T]> {
    /// Input length was checked at the public entry; resource checks precede sampling.
    /// Add encoded coefficients without plaintext scaling after body noise sampling.
    fn encrypt_encoded_kernel_to<M, Table, R>(
        &self,
        input: Polynomial<&[T]>,
        output: NttGlweCiphertext<&mut [T]>,
        params: &GlweEncryptionParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.encrypt_kernel_to(output, params, ntt, rng, workspace, |body| {
            Polynomial::new(body).add_assign(&input, params.cipher_modulus());
        });
    }

    fn encrypt_zeros_kernel_to<M, Table, R>(
        &self,
        output: NttGlweCiphertext<&mut [T]>,
        params: &GlweEncryptionParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.encrypt_kernel_to(output, params, ntt, rng, workspace, |_| {});
    }

    /// Validates output/resources, then encrypts with a statically dispatched body
    /// addition. The boundary establishes complete key polynomials and input length.
    /// `add_message` runs once after body noise sampling and before its transform.
    pub(super) fn encrypt_kernel_to<M, Table, R>(
        &self,
        mut output: NttGlweCiphertext<&mut [T]>,
        params: &GlweEncryptionParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlwePublicEncryptWorkspace<T>,
        add_message: impl FnOnce(&mut [T]),
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let poly_length = ntt.poly_length().get();
        assert_eq!(
            output.as_ref().len(),
            self.key.as_ref().len(),
            "GLWE output layout mismatch"
        );
        assert_eq!(
            workspace.ephemeral.len(),
            poly_length,
            "public encryption workspace length mismatch"
        );
        assert_eq!(
            ntt.modulus(),
            params.cipher_modulus().value(),
            "NTT ciphertext modulus mismatch"
        );

        let modulus = params.cipher_modulus();
        let ephemeral = &mut workspace.ephemeral;
        primus_distr::sample_sparse_ternary_values_to(
            ephemeral,
            params.cipher_modulus_minus_one(),
            rng,
        );
        ntt.transform_slice(ephemeral);
        let ephemeral = NttPolynomial(ephemeral.as_slice());

        let (mask, mut body) = output.a_b_mut(poly_length);
        let (public_mask, public_body) = self.key.a_b(poly_length);
        for (mut output, public_key_component) in mask.zip(public_mask) {
            primus_distr::sample_gaussian_values_to(
                output.as_mut(),
                params.noise_distribution(),
                rng,
            );
            ntt.transform_slice(output.as_mut());
            output.add_mul_assign(&public_key_component, &ephemeral, modulus);
        }

        primus_distr::sample_gaussian_values_to(body.as_mut(), params.noise_distribution(), rng);
        add_message(body.as_mut());
        ntt.transform_slice(body.as_mut());
        body.add_mul_assign(&public_body, &ephemeral, modulus);
    }
}
