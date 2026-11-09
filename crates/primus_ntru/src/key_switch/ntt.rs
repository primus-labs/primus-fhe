//! Exact NTT key switching.

use crate::{
    NlevParameters, NtruCiphertext, NtruSecretKey, NttNtruExternalProductWorkspace,
    NttNtruGadgetEncryptWorkspace, NttNtruSecretKey,
};
use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::nlev::NttNlev;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_reduce::FieldContext;
use zeroize::Zeroizing;

/// An exact NTT-domain key-switching key from an NTRU secret `f` to `f'`.
///
/// The stored key is `NLEV_{f'}[f]`. Applying its external product to
/// `NTRU_f[mu]` produces `NTRU_{f'}[mu]`.
#[derive(Clone)]
pub struct NttNtruKeySwitchingKey<T: FheUint> {
    data: NttNlev<Vec<T>>,
    poly_length: usize,
    basis: ApproxSignedBasis<T>,
}

impl<T: FheUint> NttNtruKeySwitchingKey<T> {
    /// Generates `NLEV_{f'}[f]` under `output_secret_key`.
    ///
    /// `parameters` supplies the output encryption domain and the key-switch
    /// decomposition basis `(B_ks, L_ks)`.
    ///
    /// # Panics
    ///
    /// Panics if the secret-key lengths, parameters, NTT length/modulus, or
    /// gadget workspace are incompatible. Checks precede sampling.
    ///
    /// # Correctness
    ///
    /// Every input secret coefficient must have unsigned magnitude strictly
    /// less than the target `parameters.encryption_parameters().cipher_modulus().value()`.
    /// This is the output key's modulus; validity under another modulus or
    /// the key's distribution label does not establish this bound.
    /// The output secret key must use the supplied table's NTT representation.
    pub fn generate<M, Table, R>(
        input_secret_key: &NtruSecretKey<T>,
        output_secret_key: &NttNtruSecretKey<T>,
        parameters: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttNtruGadgetEncryptWorkspace<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let poly_length = input_secret_key.poly_length();
        assert_eq!(
            output_secret_key.poly_length(),
            poly_length,
            "key-switch secret polynomial length mismatch"
        );

        output_secret_key.assert_gadget_domain(parameters, ntt, workspace);

        let mut encoded_secret = Zeroizing::new(vec![T::ZERO; poly_length]);
        parameters
            .encryption_parameters()
            .cipher_modulus()
            .encode_signed_slice_to(input_secret_key.as_slice(), encoded_secret.as_mut_slice());
        Self::generate_encoded_kernel(
            encoded_secret.as_slice(),
            output_secret_key,
            parameters,
            ntt,
            rng,
            workspace,
        )
    }

    /// Requires N canonical input coefficients and a validated output gadget domain.
    /// Encrypts the automorphed secret without constructing or inverting a new key.
    pub(crate) fn generate_encoded_kernel<M, Table, R>(
        input_secret: &[T],
        output_secret_key: &NttNtruSecretKey<T>,
        parameters: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttNtruGadgetEncryptWorkspace<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut data = NttNlev::zero(parameters.nlev_len());
        output_secret_key.encrypt_nlev_kernel_to(
            Polynomial::new(input_secret),
            data.as_mut_view(),
            parameters,
            ntt,
            rng,
            workspace,
        );
        Self {
            data,
            poly_length: parameters.poly_length().get(),
            basis: parameters.basis().clone(),
        }
    }

    /// Returns the polynomial length bound to this key.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Returns the decomposition basis and modulus used during generation.
    #[must_use]
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the raw NTT-domain NLev values.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.data.as_ref()
    }

    /// Key-switches a coefficient-domain NTRU ciphertext into `output`.
    ///
    /// Uses the polynomial length and decomposition basis stored in this key.
    /// Accumulates into `output` in NTT form, then inverse-transforms it in place;
    /// no intermediate accumulator copy or online allocation is needed.
    ///
    /// # Correctness
    ///
    /// Input coefficients must be canonical modulo `modulus`. The table must
    /// use the NTT representation used to generate this key. Decomposition
    /// and encryption errors must fit the caller's noise budget.
    ///
    /// # Panics
    ///
    /// Panics if input/output or workspace lengths, the modulus, or the NTT
    /// length/modulus do not match this key. Checks precede output writes.
    pub fn key_switch_to<M, Table, A, B>(
        &self,
        input: &NtruCiphertext<A>,
        output: &mut NtruCiphertext<B>,
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
            self.poly_length,
            "key-switch input length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.poly_length,
            "key-switch output length mismatch"
        );
        self.assert_compatible(modulus, ntt, workspace);
        self.key_switch_kernel_to(
            input.as_view(),
            output.as_mut_view(),
            modulus,
            ntt,
            workspace,
        );
    }

    /// Validates resources shared by standalone and automorphism key switching.
    pub(crate) fn assert_compatible<M, Table>(
        &self,
        modulus: M,
        ntt: &Table,
        workspace: &NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(
            workspace.poly_length().get(),
            self.poly_length,
            "key-switch workspace length mismatch"
        );
        assert_eq!(
            ntt.poly_length().get(),
            self.poly_length,
            "key-switch NTT length mismatch"
        );
        assert_eq!(
            Some(modulus.value()),
            self.basis.modulus(),
            "key-switch ciphertext modulus mismatch"
        );
        assert_eq!(
            ntt.modulus(),
            modulus.value(),
            "key-switch NTT modulus mismatch"
        );
    }

    /// Applies after the owning boundary has checked operand lengths and resources.
    pub(crate) fn key_switch_kernel_to<M, Table>(
        &self,
        input: NtruCiphertext<&[T]>,
        mut output: NtruCiphertext<&mut [T]>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        self.data.external_product_to(
            &Polynomial(input.as_ref()),
            &mut output,
            &self.basis,
            modulus,
            ntt,
            workspace,
        );
    }

    /// Key-switches into a newly allocated coefficient-domain ciphertext.
    ///
    /// Inherits [`Self::key_switch_to`]'s correctness and panic conditions.
    pub fn key_switch<M, Table, A>(
        &self,
        input: &NtruCiphertext<A>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruExternalProductWorkspace<T>,
    ) -> NtruCiphertext<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let mut output = NtruCiphertext::zero(self.poly_length);
        self.key_switch_to(input, &mut output, modulus, ntt, workspace);
        output
    }
}
