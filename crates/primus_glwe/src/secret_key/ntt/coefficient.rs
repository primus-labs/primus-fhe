//! Coefficient-domain GLWE operations using an already transformed secret.

use super::NttGlweSecretKey;
use crate::{GlweCiphertext, GlweEncryptionParameters};
use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

impl<T: FheUint> NttGlweSecretKey<T> {
    /// Encrypts after layout/table/scratch validation. Message and noise stay in
    /// coefficient form; the closure adds a message to the sampled body noise.
    pub(super) fn encrypt_coeff_kernel_to<M, Table, R>(
        &self,
        mut output: GlweCiphertext<&mut [T]>,
        params: &GlweEncryptionParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
        scratch: &mut [T],
        add_message: impl FnOnce(&mut [T]),
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let modulus = params.cipher_modulus();
        let (masks, mut body) = output.a_b_mut(self.poly_length().get());
        primus_distr::sample_gaussian_values_to(body.as_mut(), params.noise_distribution(), rng);
        add_message(body.as_mut());

        // Preserve the ordinary path's RNG order: noise, then each NTT mask.
        // Accumulate products in NTT form; message and noise stay in coefficient body.
        scratch.fill(T::ZERO);
        let mut product = NttPolynomial::new(&mut *scratch);
        let uniform = params.cipher_modulus_uniform_distr();
        for (secret, mut mask) in self.iter().zip(masks) {
            primus_distr::sample_uniform_values_to(mask.as_mut(), &uniform, rng);
            product.add_mul_assign(&NttPolynomial::new(mask.as_ref()), &secret, modulus);
            ntt_table.inverse_transform_slice(mask.as_mut());
        }
        ntt_table.inverse_transform_slice(scratch);
        body.add_assign(&Polynomial::new(scratch), modulus);
    }

    /// Extracts the coefficient phase `b - ∑ a_i * s_i` without allocating.
    /// Overwrites all N output coefficients and uses exactly N scratch elements,
    /// with no initialization required. Only masks are transformed forward;
    /// `output` temporarily holds their NTT product sum.
    ///
    /// # Correctness
    ///
    /// Input coefficients must be canonical residues modulo `modulus`. The table
    /// must use this key's NTT roots and evaluation order.
    ///
    /// # Panics
    ///
    /// Panics before writes if ciphertext, output or scratch lengths differ from
    /// the key layout, or the key/arithmetic/table moduli or table length differ.
    /// A transform panic may leave partial output or scratch.
    pub fn decrypt_phase_coeff_to<M, Table, A, B>(
        &self,
        input: &GlweCiphertext<A>,
        output: &mut Polynomial<B>,
        modulus: M,
        ntt_table: &Table,
        scratch: &mut [T],
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.assert_coeff_compatible(
            output.as_ref().len(),
            input.as_ref().len(),
            scratch.len(),
            modulus,
            ntt_table,
        );
        let (masks, body) = input.a_b(self.poly_length().get());
        output.as_mut().fill(T::ZERO);
        let mut product = NttPolynomial::new(output.as_mut());
        for (secret, mask) in self.iter().zip(masks) {
            scratch.copy_from_slice(mask.as_ref());
            ntt_table.transform_slice(scratch);
            product.add_mul_assign(&NttPolynomial::new(&*scratch), &secret, modulus);
        }
        ntt_table.inverse_transform_slice(output.as_mut());
        body.sub_rev_assign(output, modulus);
    }

    pub(super) fn assert_coeff_compatible<M, Table>(
        &self,
        polynomial_len: usize,
        ciphertext_len: usize,
        scratch_len: usize,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let n = self.poly_length().get();
        assert_eq!(polynomial_len, n, "GLWE polynomial length mismatch");
        assert_eq!(ciphertext_len, self.size.glwe_len(), "GLWE layout mismatch");
        assert_eq!(scratch_len, n, "GLWE coefficient scratch length mismatch");
        self.assert_ntt_compatible(modulus, ntt_table);
    }
}
