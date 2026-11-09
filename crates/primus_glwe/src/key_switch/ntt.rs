//! Single-modulus GLWE key switching in the NTT domain.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::GlweDimension;
use primus_lattice::{
    GadgetSize, GlweSize,
    glev::{NttGlev, NttGlevIter},
    glwe::{Glwe, NttGlwe},
};
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;
use primus_shape::PolyLength;
use zeroize::Zeroizing;

use crate::{
    GlevParameters, GlweKeySwitchingParameters, GlweSecretKey, NttGlweGadgetEncryptWorkspace,
    NttGlweSecretKey,
};

/// An NTT-domain GLWE key-switching key.
///
/// Storage is ordered by input secret polynomial. Every entry is a GLev
/// encryption of that polynomial under the output GLWE secret key.
#[derive(Clone)]
pub struct NttGlweKeySwitchingKey<T: FheUint> {
    data: Vec<T>,
    input_size: GlweSize,
    output_size: GadgetSize,
    basis: ApproxSignedBasis<T>,
}

impl<T: FheUint> NttGlweKeySwitchingKey<T> {
    /// Generates an NTT GLWE key-switching key.
    /// Input and output keys must match the layouts bound by `parameters`;
    /// their polynomial length is shared, but their dimensions may differ.
    ///
    /// # Panics
    ///
    /// Panics if key layouts, NTT length/modulus or gadget workspace differ
    /// from `parameters`. Compatibility checks precede sampling.
    ///
    /// # Correctness
    ///
    /// Every signed coefficient in `input_secret_key` must satisfy `s.unsigned_abs() < q`,
    /// where `q` is the target ciphertext modulus in `parameters`; see
    /// [`EncodeSigned::encode_signed`](primus_reduce::EncodeSigned::encode_signed).
    /// The output secret key must use the supplied table's NTT representation.
    #[must_use]
    pub fn generate<M, Table, R>(
        input_secret_key: &GlweSecretKey<T>,
        output_secret_key: &NttGlweSecretKey<T>,
        parameters: &GlweKeySwitchingParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        workspace: &mut NttGlweGadgetEncryptWorkspace<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        assert_eq!(
            input_secret_key.glwe_size(),
            parameters.input_size(),
            "input GLWE secret layout mismatch"
        );
        let output = parameters.output();
        output_secret_key.assert_gadget_compatible(output, ntt);
        workspace.assert_glev_compatible(output.size());

        Self::generate_kernel(
            input_secret_key,
            output_secret_key,
            output,
            ntt,
            rng,
            workspace,
        )
    }

    /// Generates after the caller checks input polynomial length, output key,
    /// table and GLev workspace against `params`.
    /// Automorphism also uses this path without preparing a separate KSK owner;
    /// the combined storage length is checked here for both callers.
    pub(crate) fn generate_kernel<M, Table, R>(
        input_secret_key: &GlweSecretKey<T>,
        output_secret_key: &NttGlweSecretKey<T>,
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
        let input_size = input_secret_key.glwe_size();
        let output_size = params.size();
        let glev_len = output_size.glev_len();

        let mut data = vec![
            T::ZERO;
            input_size
                .dimension()
                .get()
                .checked_mul(glev_len)
                .expect("GLWE key-switching key length overflow")
        ];
        let mut encoded_secret = Zeroizing::new(vec![T::ZERO; params.poly_length().get()]);

        for (secret_poly, entry) in input_secret_key.iter().zip(data.chunks_exact_mut(glev_len)) {
            params
                .cipher_modulus()
                .encode_signed_slice_to(secret_poly, encoded_secret.as_mut_slice());
            output_secret_key.encrypt_glev_kernel_to(
                Polynomial::new(encoded_secret.as_slice()),
                NttGlev::new(entry),
                params,
                ntt,
                rng,
                workspace,
            );
        }

        Self {
            data,
            input_size,
            output_size,
            basis: params.basis().clone(),
        }
    }

    /// Returns the input GLWE dimension.
    #[must_use]
    #[inline]
    pub fn input_dimension(&self) -> GlweDimension {
        self.input_size.dimension()
    }

    /// Returns the output GLWE dimension.
    #[must_use]
    #[inline]
    pub fn output_dimension(&self) -> GlweDimension {
        self.output_size.glwe_size().dimension()
    }

    /// Returns the polynomial length.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.input_size.poly_length()
    }

    /// Returns the input layout bound to this key.
    #[inline]
    pub fn input_size(&self) -> GlweSize {
        self.input_size
    }

    /// Returns the output gadget layout bound to this key.
    #[inline]
    pub fn output_size(&self) -> GadgetSize {
        self.output_size
    }

    /// Returns the decomposition basis bound to this key.
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the raw NTT-domain key data.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    fn iter(&self) -> NttGlevIter<'_, T> {
        NttGlevIter::new(&self.data, self.output_size.glev_len())
    }

    /// Key-switches into a newly allocated coefficient-domain ciphertext.
    ///
    /// Inherits [`Self::key_switch_to`]'s correctness and panic conditions.
    pub fn key_switch<M, Table, A>(
        &self,
        input: &Glwe<A>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweKeySwitchingWorkspace<T>,
    ) -> Glwe<Vec<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
    {
        let mut output = Glwe::zero(self.output_size.glwe_len());
        self.key_switch_to(input, &mut output, modulus, ntt, workspace);
        output
    }

    /// Key-switches a coefficient-domain GLWE ciphertext into `output`.
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
    pub fn key_switch_to<M, Table, A, B>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<B>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweKeySwitchingWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(input.as_ref().len(), self.input_size.glwe_len());
        assert_eq!(output.as_ref().len(), self.output_size.glwe_len());
        self.assert_compatible(modulus, ntt, workspace);

        self.key_switch_kernel_to(
            input.as_view(),
            output.as_mut_view(),
            modulus,
            ntt,
            workspace,
        );
    }

    /// Key-switches a validated coefficient-domain GLWE ciphertext.
    ///
    /// The caller must have validated the ciphertext layouts, modulus, NTT table, and
    /// workspace with [`Self::assert_compatible`].
    pub(crate) fn key_switch_kernel_to<M, Table>(
        &self,
        input: Glwe<&[T]>,
        mut output: Glwe<&mut [T]>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweKeySwitchingWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        debug_assert_eq!(input.as_ref().len(), self.input_size.glwe_len());
        debug_assert_eq!(output.as_ref().len(), self.output_size.glwe_len());

        let poly_length = self.input_size.poly_length().get();
        let (input_mask, input_body) = input.a_b_slices(poly_length);

        let mut workspace = workspace.as_mut();
        self.mask_product_to_accumulator(input_mask, modulus, ntt, &mut workspace);
        workspace.accumulator.write_coeff_form(&mut output, ntt);
        output.neg_assign(modulus);
        let (_, output_body) = output.a_b_mut_slices(poly_length);
        modulus.reduce_add_slice_assign(output_body, input_body);
    }

    /// Key-switches a validated coefficient-domain mask and NTT-domain body
    /// directly into an NTT GLWE.
    ///
    /// The output is overwritten with `(0, body) - sum_i mask_i * KSK_i`.
    /// The caller must have validated the layouts, modulus, NTT table, and workspace with
    /// [`Self::assert_compatible`].
    pub(crate) fn key_switch_ntt_kernel_to<M, Table>(
        &self,
        input_mask: &[T],
        input_body: NttPolynomial<&[T]>,
        output: NttGlwe<&mut [T]>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweKeySwitchingWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        debug_assert_eq!(input_mask.len(), self.input_size.mask_len());
        debug_assert_eq!(
            input_body.as_ref().len(),
            self.input_size.poly_length().get()
        );
        debug_assert_eq!(output.as_ref().len(), self.output_size.glwe_len());

        let poly_length = self.input_size.poly_length().get();
        let mut workspace = workspace.as_mut_with_accumulator(output);
        self.mask_product_to_accumulator(input_mask, modulus, ntt, &mut workspace);
        workspace.accumulator.neg_assign(modulus);
        let (_, output_body) = workspace.accumulator.a_b_mut_slices(poly_length);
        modulus.reduce_add_slice_assign(output_body, input_body.as_ref());
    }

    /// Validates the modulus, NTT table and reusable workspace shared by both output paths.
    pub(crate) fn assert_compatible<M, Table>(
        &self,
        modulus: M,
        ntt: &Table,
        workspace: &NttGlweKeySwitchingWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        assert_eq!(
            ntt.poly_length(),
            self.poly_length(),
            "key-switch NTT polynomial length mismatch"
        );
        assert_eq!(
            Some(modulus.value()),
            self.basis.modulus(),
            "key-switch ciphertext modulus mismatch"
        );
        assert_eq!(
            ntt.modulus(),
            modulus.value(),
            "NTT ciphertext modulus mismatch"
        );
        assert_eq!(
            workspace.accumulator.as_ref().len(),
            self.output_size.glwe_len(),
            "key-switch workspace layout mismatch"
        );
        assert_eq!(
            workspace.adjusted_poly.len(),
            self.input_size.poly_length().get(),
            "key-switch workspace polynomial length mismatch"
        );
    }

    /// Clears the selected NTT accumulator and stores the positive mask
    /// product `sum_i mask_i * KSK_i` in it.
    ///
    /// The caller handles the final negation and body addition.
    fn mask_product_to_accumulator<M, Table>(
        &self,
        input_mask: &[T],
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweKeySwitchingWorkspaceRefMut<'_, T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let basis = &self.basis;
        let poly_length = self.input_size.poly_length().get();
        let glwe_len = self.output_size.glwe_len();

        workspace.accumulator.set_zero();
        for (mask_poly, entry) in input_mask.chunks_exact(poly_length).zip(self.iter()) {
            basis.init_value_carry_slice_to(mask_poly, workspace.adjusted_poly, workspace.carries);

            for (decomposer, key_glwe) in basis.decomposer_iter().zip(entry.iter_ntt_glwe(glwe_len))
            {
                decomposer.decompose_slice_to(
                    workspace.adjusted_poly,
                    workspace.decomposed_ntt,
                    workspace.carries,
                );
                ntt.transform_slice(workspace.decomposed_ntt);
                workspace.accumulator.add_mul_ntt_polynomial_assign(
                    &key_glwe,
                    &NttPolynomial::new(&*workspace.decomposed_ntt),
                    modulus,
                );
            }
        }
    }
}

/// Reusable NTT workspace for GLWE key switching and LWE packing key switching.
pub struct NttGlweKeySwitchingWorkspace<T: FheUint> {
    pub(crate) adjusted_poly: Vec<T>,
    pub(crate) carries: Vec<bool>,
    pub(crate) decomposed_ntt: Vec<T>,
    pub(crate) accumulator: NttGlwe<Vec<T>>,
}

/// Mutable view of key-switch scratch with a replaceable NTT accumulator.
struct NttGlweKeySwitchingWorkspaceRefMut<'a, T: FheUint> {
    adjusted_poly: &'a mut [T],
    carries: &'a mut [bool],
    decomposed_ntt: &'a mut [T],
    accumulator: NttGlwe<&'a mut [T]>,
}

impl<T: FheUint> NttGlweKeySwitchingWorkspace<T> {
    /// Creates a workspace for the output GLWE layout.
    pub fn new(glwe_size: GlweSize) -> Self {
        let poly_length = glwe_size.poly_length().get();
        Self {
            adjusted_poly: vec![T::ZERO; poly_length],
            carries: vec![false; poly_length],
            decomposed_ntt: vec![T::ZERO; poly_length],
            accumulator: NttGlwe::zero(glwe_size.glwe_len()),
        }
    }

    #[inline]
    fn as_mut(&mut self) -> NttGlweKeySwitchingWorkspaceRefMut<'_, T> {
        NttGlweKeySwitchingWorkspaceRefMut {
            adjusted_poly: &mut self.adjusted_poly,
            carries: &mut self.carries,
            decomposed_ntt: &mut self.decomposed_ntt,
            accumulator: NttGlwe(self.accumulator.as_mut()),
        }
    }

    #[inline]
    fn as_mut_with_accumulator<'a>(
        &'a mut self,
        accumulator: NttGlwe<&'a mut [T]>,
    ) -> NttGlweKeySwitchingWorkspaceRefMut<'a, T> {
        NttGlweKeySwitchingWorkspaceRefMut {
            adjusted_poly: &mut self.adjusted_poly,
            carries: &mut self.carries,
            decomposed_ntt: &mut self.decomposed_ntt,
            accumulator,
        }
    }
}
