//! Single-modulus GLWE automorphisms evaluated with NTT key switching.

use num_traits::ConstZero;
use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::glwe::{Glwe, NttGlwe};
use primus_ntt::{NttAutomorphismPermutation, NttTable};
use primus_poly::{CoeffAutomorphismPermutation, NttPolynomial, PolynomialIterMut};
use primus_reduce::FieldContext;

use crate::{
    GlevParameters, GlweSecretKey, NttGlweGadgetEncryptWorkspace, NttGlweKeySwitchingKey,
    NttGlweKeySwitchingWorkspace, NttGlweSecretKey,
};

/// Reusable workspace for coefficient- and NTT-domain GLWE automorphisms.
pub struct NttGlweAutomorphismWorkspace<T: FheUint> {
    // All buffers share one immutable GLWE layout, checked via the nested workspace.
    transformed: Glwe<Vec<T>>,
    permuted_ntt: Vec<T>,
    key_switching: NttGlweKeySwitchingWorkspace<T>,
}

impl<T: FheUint> NttGlweAutomorphismWorkspace<T> {
    /// Creates workspace for one GLWE layout.
    pub fn new(size: primus_lattice::GlweSize) -> Self {
        Self {
            transformed: Glwe::zero(size.glwe_len()),
            permuted_ntt: vec![T::ZERO; size.poly_length().get()],
            key_switching: NttGlweKeySwitchingWorkspace::new(size),
        }
    }
}

/// Evaluation key for the GLWE automorphism `X -> X^degree`.
///
/// The key switches from the transformed secret `S(X^degree)` back to `S(X)`.
#[derive(Clone)]
pub struct NttGlweAutomorphismKey<T: FheUint> {
    degree: usize,
    key_switching: NttGlweKeySwitchingKey<T>,
    coeff_permutation: CoeffAutomorphismPermutation,
    ntt_permutation: NttAutomorphismPermutation,
}

impl<T: FheUint> NttGlweAutomorphismKey<T> {
    /// Generates an automorphism key under `secret_key`.
    ///
    /// Inherits [`NttGlweKeySwitchingKey::generate`]'s signed coefficient,
    /// key/table representation and compatibility requirements. The degree
    /// must be odd and in `[1, 2N)`; invalid degrees panic before sampling.
    ///
    /// # Correctness
    ///
    /// `secret_key` and `ntt_secret_key` must represent the same secret.
    /// This relationship is not checked.
    /// Coefficients negated by the automorphism must have representable signed
    /// negations, as required by [`CoeffAutomorphismPermutation::apply_signed_to`].
    pub fn generate<M, Table, R>(
        degree: usize,
        secret_key: &GlweSecretKey<T>,
        ntt_secret_key: &NttGlweSecretKey<T>,
        params: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlweGadgetEncryptWorkspace<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        ntt_secret_key.assert_gadget_compatible(params, ntt);
        workspace.assert_glev_compatible(params.size());
        assert_eq!(
            secret_key.glwe_size(),
            params.glwe_size(),
            "automorphism secret key layout mismatch"
        );
        Self::generate_kernel(
            degree,
            secret_key,
            ntt_secret_key,
            params,
            ntt,
            rng,
            workspace,
        )
    }

    /// Generates after checking both key layouts, the table and GLev workspace.
    /// The permutation constructors still validate the per-key degree.
    pub(crate) fn generate_kernel<M, Table, R>(
        degree: usize,
        secret_key: &GlweSecretKey<T>,
        ntt_secret_key: &NttGlweSecretKey<T>,
        params: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlweGadgetEncryptWorkspace<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let size = secret_key.glwe_size();
        let poly_len = size.poly_length().get();

        let coeff_permutation = CoeffAutomorphismPermutation::new(degree, size.poly_length());
        let ntt_permutation = NttAutomorphismPermutation::new(degree, size.poly_length());

        let mut transformed_secret = vec![T::SignedInteger::ZERO; size.mask_len()];

        for (input, output) in secret_key
            .iter()
            .zip(transformed_secret.chunks_exact_mut(poly_len))
        {
            coeff_permutation.apply_signed_to::<T>(input, output);
        }

        let transformed_secret = GlweSecretKey::new(transformed_secret, size, secret_key.distr());
        let key_switching = NttGlweKeySwitchingKey::generate_kernel(
            &transformed_secret,
            ntt_secret_key,
            params,
            ntt,
            rng,
            workspace,
        );

        Self {
            degree,
            key_switching,
            coeff_permutation,
            ntt_permutation,
        }
    }

    /// Returns the odd automorphism degree in `[1, 2N)`.
    #[inline]
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the decomposition basis bound to this key.
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        self.key_switching.basis()
    }

    /// Applies the automorphism and writes a coefficient-domain GLWE under the
    /// original secret key.
    ///
    /// Uses the layout and decomposition basis stored in this key.
    ///
    /// # Correctness
    ///
    /// Input coefficients must be canonical modulo `modulus`. The NTT table
    /// must use the transform representation used to generate this key.
    ///
    /// # Panics
    ///
    /// Panics if input/output or workspace layouts, the modulus, or the NTT
    /// length/modulus do not match the key. Checks precede output writes.
    pub fn apply_to<M, Table, A, B>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweAutomorphismWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            input.as_ref().len(),
            self.key_switching.input_size().glwe_len(),
            "automorphism input layout mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.key_switching.output_size().glwe_len(),
            "automorphism output layout mismatch"
        );
        self.assert_compatible(modulus, ntt, workspace);

        self.apply_kernel_to(
            input.as_view(),
            output.as_mut_view(),
            modulus,
            ntt,
            workspace,
        );
    }

    /// Applies the automorphism after the caller has validated the modulus, NTT table,
    /// ciphertext layouts, and workspace.
    pub(crate) fn apply_kernel_to<M, Table>(
        &self,
        input: Glwe<&[T]>,
        output: Glwe<&mut [T]>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweAutomorphismWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let poly_length = self.key_switching.poly_length().get();
        debug_assert_eq!(
            input.as_ref().len(),
            self.key_switching.input_size().glwe_len()
        );
        debug_assert_eq!(
            output.as_ref().len(),
            self.key_switching.output_size().glwe_len()
        );
        debug_assert_eq!(
            workspace.transformed.as_ref().len(),
            self.key_switching.input_size().glwe_len()
        );

        for (input_poly, mut output_poly) in input
            .iter_poly(poly_length)
            .zip(workspace.transformed.iter_poly_mut(poly_length))
        {
            self.coeff_permutation
                .apply_to(input_poly.as_ref(), output_poly.as_mut(), modulus);
        }

        self.key_switching.key_switch_kernel_to(
            workspace.transformed.as_view(),
            output,
            modulus,
            ntt,
            &mut workspace.key_switching,
        );
    }

    /// Applies the automorphism directly to an NTT-domain GLWE ciphertext.
    ///
    /// Mask polynomials are permuted and inverse-transformed for key-switch
    /// decomposition. The body polynomial is permuted and combined entirely
    /// in the NTT domain.
    ///
    /// Inherits [`Self::apply_to`]'s compatibility and canonical residue
    /// requirements. The input must also use this key's NTT representation.
    pub fn apply_ntt_to<M, Table, A, B>(
        &self,
        input: &NttGlwe<A>,
        output: &mut NttGlwe<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweAutomorphismWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            input.as_ref().len(),
            self.key_switching.input_size().glwe_len(),
            "NTT automorphism input layout mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            self.key_switching.output_size().glwe_len(),
            "NTT automorphism output layout mismatch"
        );
        self.assert_compatible(modulus, ntt, workspace);

        self.apply_ntt_kernel_to(
            input.as_view(),
            output.as_mut_view(),
            modulus,
            ntt,
            workspace,
        );
    }

    /// Applies the NTT automorphism after the caller has validated the modulus, NTT table,
    /// ciphertext layouts, and workspace.
    fn apply_ntt_kernel_to<M, Table>(
        &self,
        input: NttGlwe<&[T]>,
        output: NttGlwe<&mut [T]>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweAutomorphismWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let poly_length = self.key_switching.poly_length().get();
        debug_assert_eq!(
            input.as_ref().len(),
            self.key_switching.input_size().glwe_len()
        );
        debug_assert_eq!(
            output.as_ref().len(),
            self.key_switching.output_size().glwe_len()
        );
        debug_assert_eq!(workspace.permuted_ntt.len(), poly_length);

        let (input_mask, input_body) = input.a_b(poly_length);
        let NttGlweAutomorphismWorkspace {
            transformed,
            permuted_ntt,
            key_switching,
        } = workspace;

        let (transformed_mask, _) = transformed.a_b_mut_slices(poly_length);
        for (input_poly, mut output_poly) in
            input_mask.zip(PolynomialIterMut::new(transformed_mask, poly_length))
        {
            self.ntt_permutation
                .apply_to(input_poly.as_ref(), permuted_ntt);
            ntt.inverse_transform_slice(permuted_ntt);
            output_poly.as_mut().copy_from_slice(permuted_ntt);
        }

        self.ntt_permutation
            .apply_to(input_body.as_ref(), permuted_ntt);
        self.key_switching.key_switch_ntt_kernel_to(
            transformed_mask,
            NttPolynomial::new(permuted_ntt.as_slice()),
            output,
            modulus,
            ntt,
            key_switching,
        );
    }

    /// Validates the modulus, NTT table and reusable workspace shared by both
    /// automorphism output paths.
    pub(crate) fn assert_compatible<M, Table>(
        &self,
        modulus: M,
        ntt: &Table,
        workspace: &NttGlweAutomorphismWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        self.key_switching
            .assert_compatible(modulus, ntt, &workspace.key_switching);
    }
}
