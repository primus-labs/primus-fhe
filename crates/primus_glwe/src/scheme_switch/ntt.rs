//! Scheme switching from GLev to NTT GGSW ciphertexts.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::{
    GadgetSize,
    ggsw::{NttGgsw, NttGgswIter},
    glev::Glev,
    workspace::NttGlweExternalProductWorkspace,
};
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_reduce::FieldContext;
use zeroize::Zeroizing;

use crate::{GlevParameters, GlweSecretKey, NttGlweGadgetEncryptWorkspace, NttGlweSecretKey};

/// NTT GGSW encryptions of the negated GLWE secret polynomials.
///
/// One key ciphertext is stored for every mask row. The GGSW body row is
/// copied directly from the input GLev during evaluation, avoiding an
/// unnecessary encryption of one and external product.
#[derive(Clone)]
pub struct NttGlweSchemeSwitchKey<T: FheUint> {
    data: Vec<T>,
    key_size: GadgetSize,
    output_size: GadgetSize,
    key_basis: ApproxSignedBasis<T>,
}

impl<T: FheUint> NttGlweSchemeSwitchKey<T> {
    /// Generates a scheme-switching key for one output GGSW layout.
    ///
    /// # Panics
    ///
    /// Panics if key/output layouts, NTT length/modulus or gadget workspace
    /// are incompatible with `key_parameters`, or key storage length overflows.
    /// Checks precede sampling.
    ///
    /// # Correctness
    ///
    /// Every signed coefficient in `secret_key` must satisfy `s.unsigned_abs() < q`,
    /// where `q` is the ciphertext modulus in `key_parameters`; see
    /// [`EncodeSigned::encode_signed`](primus_reduce::EncodeSigned::encode_signed).
    /// `secret_key` and `ntt_secret_key` must represent the same secret; this
    /// relationship is not checked. The NTT key must use the supplied table's representation.
    pub fn generate<M, Table, R>(
        secret_key: &GlweSecretKey<T>,
        ntt_secret_key: &NttGlweSecretKey<T>,
        output_size: GadgetSize,
        key_parameters: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlweGadgetEncryptWorkspace<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        ntt_secret_key.assert_gadget_compatible(key_parameters, ntt);
        workspace.assert_ggsw_compatible(key_parameters.size());
        let key_size = key_parameters.size();
        assert_eq!(secret_key.glwe_size(), key_size.glwe_size());
        assert_eq!(output_size.glwe_size(), key_size.glwe_size());

        let dimension = key_size.glwe_size().dimension();
        let mut data = vec![
            T::ZERO;
            dimension
                .get()
                .checked_mul(key_size.ggsw_len())
                .expect("scheme-switch key length overflow")
        ];
        let mut negated_secret =
            Zeroizing::new(vec![T::ZERO; key_size.glwe_size().poly_length().get()]);
        let modulus = key_parameters.cipher_modulus();

        for (secret_polynomial, key_ciphertext) in secret_key
            .iter()
            .zip(data.chunks_exact_mut(key_size.ggsw_len()))
        {
            modulus.encode_signed_slice_to(secret_polynomial, negated_secret.as_mut_slice());
            modulus.reduce_neg_slice_assign(negated_secret.as_mut_slice());
            ntt_secret_key.encrypt_ggsw_kernel_to(
                Polynomial::new(negated_secret.as_slice()),
                NttGgsw::new(key_ciphertext),
                key_parameters,
                ntt,
                rng,
                workspace,
            );
        }

        Self {
            data,
            key_size,
            output_size,
            key_basis: key_parameters.basis().clone(),
        }
    }

    /// Returns the scheme-switching key gadget layout.
    #[inline]
    pub fn key_size(&self) -> GadgetSize {
        self.key_size
    }

    /// Returns the output GGSW layout.
    #[inline]
    pub fn output_size(&self) -> GadgetSize {
        self.output_size
    }

    /// Returns the decomposition basis bound to the scheme-switching key.
    #[inline]
    pub fn key_basis(&self) -> &ApproxSignedBasis<T> {
        &self.key_basis
    }

    /// Converts a coefficient-domain GLev into an NTT-domain GGSW.
    ///
    /// Uses the stored layout and key decomposition basis. The output preserves
    /// the input GLev's gadget scaling; the key basis only decomposes products.
    ///
    /// Bind `workspace` to [`Self::key_size`]. To reuse it temporarily with a
    /// different decomposition depth, use
    /// [`NttGlweExternalProductWorkspace::with_rebound`], which restores the key
    /// layout after the call.
    ///
    /// # Correctness
    ///
    /// The input GLev must be encrypted under the secret used to generate this key.
    /// Input coefficients must be canonical modulo `modulus`. The NTT table
    /// must use the transform representation used to generate this key.
    ///
    /// # Panics
    ///
    /// Panics if input/output or workspace layouts, the modulus, or the NTT
    /// length/modulus do not match the key. Checks precede output writes.
    pub fn apply_to<M, Table, A, B>(
        &self,
        input: &Glev<A>,
        output: &mut NttGgsw<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            input.as_ref().len(),
            self.output_size.glev_len(),
            "scheme-switch input GLev layout mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.output_size.ggsw_len(),
            "scheme-switch output GGSW layout mismatch"
        );
        assert_eq!(
            ntt.poly_length().get(),
            self.key_size.glwe_size().poly_length().get(),
            "scheme-switch NTT polynomial length mismatch"
        );
        assert_eq!(
            Some(modulus.value()),
            self.key_basis.modulus(),
            "scheme-switch ciphertext modulus mismatch"
        );
        assert_eq!(
            ntt.modulus(),
            modulus.value(),
            "NTT ciphertext modulus mismatch"
        );
        assert_eq!(
            workspace.size(),
            self.key_size,
            "scheme-switch workspace layout mismatch"
        );

        let glwe_size = self.output_size.glwe_size();
        let poly_length = glwe_size.poly_length().get();
        let glwe_len = glwe_size.glwe_len();
        let output_glev_len = self.output_size.glev_len();
        let key_basis = &self.key_basis;

        let mut output_rows = output.iter_ntt_glev_mut(output_glev_len);
        for (key, mut output_row) in
            NttGgswIter::new(&self.data, self.key_size.ggsw_len()).zip(&mut output_rows)
        {
            for (input_glwe, mut output_glwe) in input
                .iter_glwe(glwe_len)
                .zip(output_row.iter_ntt_glwe_mut(glwe_len))
            {
                key.external_product_ntt_to(
                    &input_glwe,
                    &mut output_glwe,
                    key_basis,
                    modulus,
                    ntt,
                    workspace,
                );
            }
        }

        let mut body_row = output_rows
            .next()
            .expect("scheme-switch output is missing its body row");
        for (input_glwe, mut output_glwe) in input
            .iter_glwe(glwe_len)
            .zip(body_row.iter_ntt_glwe_mut(glwe_len))
        {
            output_glwe.as_mut().copy_from_slice(input_glwe.as_ref());
            for polynomial in output_glwe.as_mut().chunks_exact_mut(poly_length) {
                ntt.transform_slice(polynomial);
            }
        }
        debug_assert!(output_rows.next().is_none());
    }
}
