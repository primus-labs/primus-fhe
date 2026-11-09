//! Batch encryption of constant polynomials with an NTT secret key.

use super::{NttGlweGadgetEncryptWorkspace, NttGlweSecretKey};
use crate::{GlevParameters, NttGgswCiphertext};
use primus_integer::FheUint;
use primus_lattice::ggsw::Ggsw;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

impl<T: FheUint> NttGlweSecretKey<T> {
    /// Encrypts a batch of constant ring polynomials into consecutive NTT GGSWs.
    ///
    /// Each `input[i]` represents the polynomial `input[i] + 0X + ... + 0X^(N-1)`.
    /// Applies the gadget basis without plaintext encoding, as in [`Self::encrypt_ggsw_to`].
    ///
    /// `output` uses `[input][row][level][component][coefficient]` storage and
    /// must contain exactly `input.len() * params.ggsw_len()` values. Reuses
    /// `workspace` without allocating and checks shared resources once per batch.
    /// Empty input with empty output is accepted after resource validation and
    /// consumes no randomness.
    ///
    /// # Correctness
    ///
    /// Each input must be a canonical residue modulo `params.cipher_modulus()`.
    /// This key must use the supplied table's NTT representation.
    ///
    /// # Panics
    ///
    /// Panics on incompatible key, table, workspace, output length, or length
    /// overflow. Compatibility checks precede all output writes and sampling.
    /// A panicking RNG or transform can leave partial output and modified workspace.
    pub fn encrypt_ggsw_constant_batch_to<M, Table, R>(
        &self,
        input: &[T],
        output: &mut [T],
        params: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlweGadgetEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.assert_gadget_compatible(params, ntt);
        workspace.assert_ggsw_compatible(params.size());
        let ggsw_len = params.ggsw_len();
        let output_len = input
            .len()
            .checked_mul(ggsw_len)
            .expect("NTT GGSW batch length overflow");
        assert_eq!(
            output.len(),
            output_len,
            "NTT GGSW batch output layout mismatch"
        );

        let modulus = params.cipher_modulus();
        for (&constant, output) in input.iter().zip(output.chunks_exact_mut(ggsw_len)) {
            // A constant evaluates to itself at every NTT root. Scale once per
            // level and broadcast, avoiding a full NTT and N modular products.
            for (scalar, transformed) in params.basis().scalar_iter().zip(
                workspace
                    .level_transforms
                    .chunks_exact_mut(self.poly_length().get()),
            ) {
                transformed.fill(modulus.reduce_mul(constant, scalar));
            }
            self.encrypt_ggsw_from_levels_to(
                NttGgswCiphertext::new(output),
                params,
                ntt,
                rng,
                workspace,
            );
        }
    }

    /// Encrypts constant ring polynomials into consecutive coefficient GGSWs.
    ///
    /// With the same RNG state, the output equals
    /// [`Self::encrypt_ggsw_constant_batch_to`] followed by inverse NTTs, without
    /// transforming the sampled body noise forward. Output layout is
    /// `[input][row][level][component][coefficient]`, with exactly
    /// `input.len() * params.ggsw_len()` values. Reuses the polynomial buffer in
    /// `workspace` without allocating; its level count need not match. Empty input
    /// and output still validate resources but consume no randomness.
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::encrypt_ggsw_constant_batch_to`]'s canonical input and
    /// NTT representation requirements.
    ///
    /// # Panics
    ///
    /// Panics before sampling or writes on incompatible key, table, polynomial
    /// workspace, output length, or length overflow. RNG/NTT panics can leave
    /// partial output and modified workspace.
    pub fn encrypt_ggsw_constant_batch_coeff_to<M, Table, R>(
        &self,
        input: &[T],
        output: &mut [T],
        params: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlweGadgetEncryptWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.assert_gadget_compatible(params, ntt);
        workspace.assert_glev_compatible(params.size());
        let ggsw_len = params.ggsw_len();
        let expected = input
            .len()
            .checked_mul(ggsw_len)
            .expect("coefficient GGSW batch length overflow");
        assert_eq!(
            output.len(),
            expected,
            "coefficient GGSW batch output layout mismatch"
        );

        let n = self.poly_length().get();
        let modulus = params.cipher_modulus();
        for (&constant, block) in input.iter().zip(output.chunks_exact_mut(ggsw_len)) {
            for (row, mut glev) in Ggsw::new(block)
                .iter_glev_mut(params.glev_len())
                .enumerate()
            {
                for (scalar, mut glwe) in params
                    .basis()
                    .scalar_iter()
                    .zip(glev.iter_glwe_mut(params.glwe_len()))
                {
                    self.encrypt_coeff_kernel_to(
                        glwe.as_mut_view(),
                        params.encryption_parameters(),
                        ntt,
                        rng,
                        workspace.encoded.as_mut(),
                        |_| {},
                    );
                    // Add the gadget diagonal after accumulating the original
                    // masks into the body, exactly as in NTT GGSW encryption.
                    modulus.reduce_add_assign(
                        &mut glwe.as_mut()[row * n],
                        modulus.reduce_mul(constant, scalar),
                    );
                }
            }
        }
    }
}
