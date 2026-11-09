//! NLev and NGSW encryption.

use super::{NttNtruGadgetEncryptWorkspace, NttNtruSecretKey};
use crate::{NlevParameters, NttNgswCiphertext, NttNlevCiphertext, NttNtruCiphertext};
use primus_data::{Data, DataMut};
use primus_integer::{FheUint, SignedInteger};
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

impl<T: FheUint> NttNtruSecretKey<T> {
    /// Generates an NTT NLev encryption of a polynomial already encoded in `[0, q)`.
    ///
    /// # Correctness
    ///
    /// Input coefficients must be canonical under the parameter modulus. The
    /// secret key must use the supplied NTT roots and evaluation order.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes if the key/parameter/table moduli or
    /// lengths, input/output lengths or workspace length disagree.
    pub fn encrypt_nlev_to<M, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut NttNlevCiphertext<B>,
        params: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttNtruGadgetEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_gadget_domain(params, ntt, workspace);
        assert_eq!(
            message.as_ref().len(),
            self.poly_length(),
            "gadget input length mismatch"
        );
        assert_eq!(
            result.as_ref().len(),
            params.nlev_len(),
            "gadget output length mismatch"
        );

        self.encrypt_nlev_kernel_to(
            message.as_view(),
            result.as_mut_view(),
            params,
            ntt,
            rng,
            workspace,
        );
    }

    /// Adds each scaled message before multiplication by the inverse secret, giving
    /// NLev phase `g_l * message + e_l`. The caller validates complete operands,
    /// the key/parameter/table domain and polynomial scratch.
    pub(crate) fn encrypt_nlev_kernel_to<M, Table, R>(
        &self,
        message: Polynomial<&[T]>,
        mut result: NttNlevCiphertext<&mut [T]>,
        params: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttNtruGadgetEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let poly_length = self.poly_length();
        let ntru_params = params.encryption_parameters();
        let modulus = ntru_params.cipher_modulus();
        for (scalar, level) in params
            .basis()
            .scalar_iter()
            .zip(result.iter_ntt_ntru_mut(poly_length))
        {
            message.mul_scalar_to(scalar, &mut workspace.encoded, modulus);
            self.encrypt_encoded_to_unchecked(
                workspace.encoded.as_view(),
                level,
                ntru_params,
                ntt,
                rng,
            );
        }
    }

    /// Encrypts a constant ring element as NLev without plaintext scaling.
    /// Each level has phase `g_l * input + e_l`; input `1` initializes an
    /// encrypted accumulator through an NLev external product.
    /// Reuses output and scratch, zeroing the coefficient tail once per call.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes for incompatible key/parameter/table,
    /// output or workspace lengths or a constant outside `[0, q)`.
    ///
    /// # Correctness
    ///
    /// The secret key must use the supplied NTT roots and evaluation order.
    pub fn encrypt_nlev_constant_to<M, Table, R, B>(
        &self,
        input: T,
        output: &mut NttNlevCiphertext<B>,
        params: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttNtruGadgetEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        B: DataMut<Elem = T>,
    {
        self.assert_gadget_domain(params, ntt, workspace);
        assert_eq!(
            output.as_ref().len(),
            params.nlev_len(),
            "NLev output length mismatch"
        );
        let modulus = params.encryption_parameters().cipher_modulus();
        assert!(
            input < modulus.value(),
            "NLev constant must be a canonical residue"
        );
        self.encrypt_nlev_constant_kernel_to(
            input,
            output.as_mut_view(),
            params,
            ntt,
            rng,
            workspace,
        );
    }

    /// Encrypts a validated canonical constant after the caller checks resources and output.
    /// Clears the coefficient scratch once, then changes only its constant term per level.
    fn encrypt_nlev_constant_kernel_to<M, Table, R>(
        &self,
        input: T,
        mut output: NttNlevCiphertext<&mut [T]>,
        params: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttNtruGadgetEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let modulus = params.encryption_parameters().cipher_modulus();
        workspace.encoded.as_mut().fill(T::ZERO);
        for (scalar, level) in params
            .basis()
            .scalar_iter()
            .zip(output.iter_ntt_ntru_mut(self.poly_length()))
        {
            workspace.encoded.as_mut()[0] = modulus.reduce_mul(input, scalar);
            self.encrypt_encoded_to_unchecked(
                workspace.encoded.as_view(),
                level,
                params.encryption_parameters(),
                ntt,
                rng,
            );
        }
    }

    /// Generates an NTT NGSW encryption of a polynomial already encoded in `[0, q)`.
    /// Inherits [`Self::encrypt_nlev_to`]'s representation and failure contracts.
    pub fn encrypt_ngsw_to<M, Table, R, A, B>(
        &self,
        message: &Polynomial<A>,
        result: &mut NttNgswCiphertext<B>,
        params: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttNtruGadgetEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_gadget_domain(params, ntt, workspace);
        assert_eq!(
            message.as_ref().len(),
            self.poly_length(),
            "gadget input length mismatch"
        );
        assert_eq!(
            result.as_ref().len(),
            params.nlev_len(),
            "gadget output length mismatch"
        );

        self.encrypt_ngsw_kernel_to(
            message.as_view(),
            result.as_mut_view(),
            params,
            ntt,
            rng,
            workspace,
        );
    }

    /// Adds the scaled message in NTT form after encrypting zero, giving NGSW phase
    /// `f * g_l * message + e_l`. The caller validates complete operands,
    /// the key/parameter/table domain and polynomial scratch.
    fn encrypt_ngsw_kernel_to<M, Table, R>(
        &self,
        message: Polynomial<&[T]>,
        mut result: NttNgswCiphertext<&mut [T]>,
        params: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttNtruGadgetEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let poly_length = self.poly_length();
        let ntru_params = params.encryption_parameters();
        let modulus = ntru_params.cipher_modulus();
        for (scalar, mut level) in params
            .basis()
            .scalar_iter()
            .zip(result.iter_ntt_ntru_mut(poly_length))
        {
            message.mul_scalar_to(scalar, &mut workspace.encoded, modulus);
            ntt.transform_slice(workspace.encoded.as_mut());
            self.encrypt_zeros_to_unchecked(level.as_mut_view(), ntru_params, ntt, rng);
            NttPolynomial(level.as_mut())
                .add_assign(&NttPolynomial(workspace.encoded.as_ref()), modulus);
        }
    }

    /// Encrypts signed constants into contiguous NTT NGSWs without plaintext scaling.
    ///
    /// Accepts coefficient-secret slices directly, including negative constants.
    /// Output uses `[input][level][NTT coefficient]` layout and must contain
    /// `input.len() * params.nlev_len()` values. Checks the complete batch before
    /// sampling or writes; empty input/output consumes no randomness.
    /// A constant has the same value at every NTT evaluation, so this path needs
    /// neither polynomial scratch nor a message transform.
    ///
    /// # Panics
    ///
    /// Panics on incompatible key/parameters/table, output length or size overflow,
    /// or if any constant's unsigned magnitude is not below the modulus.
    /// A panicking RNG or transform can leave partial output.
    ///
    /// # Correctness
    ///
    /// The secret key must use the supplied NTT roots and evaluation order.
    pub fn encrypt_ngsw_signed_constant_batch_to<M, Table, R>(
        &self,
        input: &[T::SignedInteger],
        output: &mut [T],
        params: &NlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.assert_domain(params.encryption_parameters(), ntt);
        let nlev_len = params.nlev_len();
        let expected = input
            .len()
            .checked_mul(nlev_len)
            .expect("NGSW batch length overflow");
        assert_eq!(output.len(), expected, "NGSW batch output length mismatch");
        let modulus = params.encryption_parameters().cipher_modulus();
        // Scan all secret coefficients rather than stopping at the first bad one.
        assert!(
            input.iter().fold(true, |valid, &value| valid
                & (value.unsigned_abs() < modulus.value())),
            "NGSW constant magnitude must be below the modulus"
        );
        for (&value, block) in input.iter().zip(output.chunks_exact_mut(nlev_len)) {
            let constant = modulus.encode_signed(value);
            for (scalar, level) in params
                .basis()
                .scalar_iter()
                .zip(block.chunks_exact_mut(self.poly_length()))
            {
                let mut level = NttNtruCiphertext::new(level);
                self.encrypt_zeros_to_unchecked(
                    level.as_mut_view(),
                    params.encryption_parameters(),
                    ntt,
                    rng,
                );
                let diagonal = modulus.reduce_mul(constant, scalar);
                for coefficient in level.as_mut() {
                    *coefficient = modulus.reduce_add(*coefficient, diagonal);
                }
            }
        }
    }

    /// Checks shared generation resources before standalone or batched sampling.
    pub(crate) fn assert_gadget_domain<M, Table>(
        &self,
        params: &NlevParameters<T, M>,
        ntt: &Table,
        workspace: &NttNtruGadgetEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        self.assert_domain(params.encryption_parameters(), ntt);
        assert_eq!(workspace.encoded.as_ref().len(), self.poly_length());
    }
}
