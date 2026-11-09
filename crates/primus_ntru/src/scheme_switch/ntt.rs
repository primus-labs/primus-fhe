//! Exact modular NLev-to-NGSW scheme switching under one NTRU secret.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_reduce::FieldContext;
use zeroize::Zeroizing;

use crate::{
    NlevCiphertext, NlevParameters, NtruSecretKey, NttNgswCiphertext,
    NttNtruExternalProductWorkspace, NttNtruGadgetEncryptWorkspace, NttNtruSecretKey,
};

/// Converts `NLev_f[m]` to `NGSW_f[m]`, preserving the input gadget scalars.
///
/// The evaluation key is `NGSW_f[f]`, with phase `g_key,j*f² + E_j`.
/// Its decomposition basis is independent of the input/output basis.
/// For `f*c_l = g_out,l*m + e_l` and decomposition reconstruction `c_l+delta_l`,
/// the output phase is
/// `g_out,l*f*m + f*e_l + f²*delta_l + sum_j digit_j*E_j`.
///
/// Publishing this secret-dependent evaluation key requires an appropriate
/// key-dependent-message/circular-security assumption. Algebraic correctness
/// does not establish that assumption or a usable noise/security parameter set.
#[derive(Clone)]
pub struct NttNtruSchemeSwitchKey<T: FheUint> {
    data: NttNgswCiphertext<Vec<T>>,
    poly_length: usize,
    key_basis: ApproxSignedBasis<T>,
    output_basis: ApproxSignedBasis<T>,
    output_len: usize,
}

impl<T: FheUint> NttNtruSchemeSwitchKey<T> {
    /// Generates `NGSW_f[f]` without explicitly forming the polynomial `f²`.
    ///
    /// # Correctness
    /// Both secrets represent the same polynomial in this modulus and NTT
    /// representation. Signed coefficient magnitudes are strictly below q.
    /// The caller must justify publishing a secret-dependent message and budget
    /// the errors described on [`Self`], including multiplication by f and f².
    ///
    /// # Panics
    /// Panics before sampling if the secret lengths, basis moduli, NTT or
    /// generation workspace disagree, or the output layout overflows usize.
    #[must_use]
    pub fn generate<M, Table, R>(
        secret_key: &NtruSecretKey<T>,
        ntt_secret_key: &NttNtruSecretKey<T>,
        output_basis: &ApproxSignedBasis<T>,
        key_parameters: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttNtruGadgetEncryptWorkspace<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let n = key_parameters.poly_length().get();
        assert_eq!(
            secret_key.poly_length(),
            n,
            "scheme-switch secret length mismatch"
        );
        assert_eq!(
            output_basis.modulus(),
            key_parameters.basis().modulus(),
            "scheme-switch output basis modulus mismatch"
        );
        let output_len = n
            .checked_mul(output_basis.level_count().get())
            .expect("scheme-switch output length overflow");
        let mut encoded = Zeroizing::new(vec![T::ZERO; n]);
        key_parameters
            .encryption_parameters()
            .cipher_modulus()
            .encode_signed_slice_to(secret_key.as_slice(), encoded.as_mut_slice());
        let mut data = NttNgswCiphertext::zero(key_parameters.nlev_len());
        // encrypt_ngsw_to checks the remaining generation resources before RNG
        // use. Adding g_j*f to ciphertexts gives phase g_j*f², without a signed
        // host-integer square or an extra secret-key inverse.
        ntt_secret_key.encrypt_ngsw_to(
            &Polynomial(encoded.as_slice()),
            &mut data,
            key_parameters,
            ntt,
            rng,
            workspace,
        );
        Self {
            data,
            poly_length: n,
            key_basis: key_parameters.basis().clone(),
            output_basis: output_basis.clone(),
            output_len,
        }
    }

    /// Returns the unchanged NTRU polynomial length.
    #[must_use]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Returns the basis used to decompose each input ciphertext polynomial.
    #[must_use]
    pub fn key_basis(&self) -> &ApproxSignedBasis<T> {
        &self.key_basis
    }

    /// Returns the basis shared by the input NLev and output NGSW.
    #[must_use]
    pub fn output_basis(&self) -> &ApproxSignedBasis<T> {
        &self.output_basis
    }

    /// Returns the raw NTT evaluation-key rows in key-basis order.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        self.data.as_ref()
    }

    /// Overwrites a transformed NGSW from a coefficient NLev under the same f.
    /// Uses the existing external-product workspace without online allocation.
    ///
    /// # Correctness
    /// Input levels use [`Self::output_basis`] scalars, order and secret. Their
    /// coefficients are canonical modulo q. The supplied NTT representation is
    /// the one used during generation. The caller budgets the input error
    /// multiplied by f, decomposition error multiplied by f², and evaluation-key
    /// error; see [`Self`]. A matching row count alone does not establish a basis.
    ///
    /// # Panics
    /// Panics before writes if input/output lengths, modulus, NTT or workspace
    /// do not match this key. Each output has N*L_output values.
    pub fn apply_to<M, Table, A, B>(
        &self,
        input: &NlevCiphertext<A>,
        output: &mut NttNgswCiphertext<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            input.as_ref().len(),
            self.output_len,
            "scheme-switch input length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.output_len,
            "scheme-switch output length mismatch"
        );
        assert_eq!(
            workspace.poly_length().get(),
            self.poly_length,
            "scheme-switch workspace length mismatch"
        );
        assert_eq!(
            ntt.poly_length().get(),
            self.poly_length,
            "scheme-switch NTT length mismatch"
        );
        assert_eq!(
            Some(modulus.value()),
            self.key_basis.modulus(),
            "scheme-switch modulus mismatch"
        );
        assert_eq!(
            ntt.modulus(),
            modulus.value(),
            "scheme-switch NTT modulus mismatch"
        );
        for (input, mut output) in input
            .iter_ntru(self.poly_length)
            .zip(output.iter_ntt_ntru_mut(self.poly_length))
        {
            self.data.external_product_ntt_to(
                &input,
                &mut output,
                &self.key_basis,
                modulus,
                ntt,
                workspace,
            );
        }
    }
}
