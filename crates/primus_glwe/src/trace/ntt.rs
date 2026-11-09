//! Homomorphic trace for single-modulus coefficient-domain GLWE ciphertexts.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_factor::ShoupFactor;
use primus_integer::FheUint;
use primus_lattice::{GlweSize, glwe::Glwe};
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use crate::{
    GlevParameters, GlweSecretKey, NttGlweAutomorphismKey, NttGlweAutomorphismWorkspace,
    NttGlweGadgetEncryptWorkspace, NttGlweSecretKey,
};

/// Reusable workspace for homomorphic GLWE trace evaluation.
pub struct NttGlweTraceWorkspace<T: FheUint> {
    // All buffers share one immutable GLWE layout, checked via the nested workspace.
    pub(super) automorphism_output: Glwe<Vec<T>>,
    pub(super) automorphism: NttGlweAutomorphismWorkspace<T>,
}

impl<T: FheUint> NttGlweTraceWorkspace<T> {
    /// Creates trace workspace for one GLWE layout.
    pub fn new(size: GlweSize) -> Self {
        Self {
            automorphism_output: Glwe::zero(size.glwe_len()),
            automorphism: NttGlweAutomorphismWorkspace::new(size),
        }
    }
}

/// The `log2(N)` automorphism keys shared by trace, coefficient projection
/// and related-key packing. Inputs and outputs remain in coefficient form.
#[derive(Clone)]
pub struct NttGlweTraceKey<T: FheUint> {
    pub(super) automorphism_keys: Vec<NttGlweAutomorphismKey<T>>,
    pub(super) glwe_size: GlweSize,
    pub(super) inverse_two: T,
    // Entry j is the Shoup factor for 1 / 2^j, including full expansion at log2(N).
    pub(super) inverse_expansion_lengths: Vec<ShoupFactor<T>>,
}

impl<T: FheUint> NttGlweTraceKey<T> {
    /// Generates the automorphism keys for degrees `N + 1, N/2 + 1, ...,
    /// 3`.
    ///
    /// Inherits [`NttGlweAutomorphismKey::generate`]'s correctness and panic conditions.
    ///
    /// # Panics
    /// Panics if the ciphertext modulus is not below `2^(T::BITS - 1)`,
    /// as required by the precomputed [`ShoupFactor`] for normalization.
    pub fn generate<M, Table, R>(
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
        let glwe_size = secret_key.glwe_size();
        assert_eq!(
            glwe_size,
            params.glwe_size(),
            "trace secret key layout mismatch"
        );
        let modulus = params.cipher_modulus();
        assert!(
            modulus.value() < (T::ONE << (T::BITS - 1)),
            "trace normalization requires modulus below 2^(T::BITS - 1)"
        );
        let log_n = glwe_size.poly_length().log_n();
        let automorphism_keys = (1..=log_n)
            .rev()
            .map(|shift| (1usize << shift) + 1)
            .map(|degree| {
                NttGlweAutomorphismKey::generate_kernel(
                    degree,
                    secret_key,
                    ntt_secret_key,
                    params,
                    ntt,
                    rng,
                    workspace,
                )
            })
            .collect();
        let inverse_two = (modulus.value() >> 1u32) + T::ONE;
        let mut inverse = T::ONE;
        let mut inverse_expansion_lengths = Vec::with_capacity(log_n as usize + 1);
        for _ in 0..=log_n {
            inverse_expansion_lengths.push(ShoupFactor::new(inverse, modulus.value()));
            inverse = (inverse >> 1u32) + (inverse & T::ONE) * inverse_two;
        }
        Self {
            inverse_expansion_lengths,
            automorphism_keys,
            glwe_size,
            inverse_two,
        }
    }

    /// Returns the coefficient layout shared by the input, output and trace keys.
    #[must_use]
    pub fn glwe_size(&self) -> GlweSize {
        self.glwe_size
    }

    /// Returns the number of automorphism evaluations in one trace.
    #[inline]
    pub fn automorphism_count(&self) -> usize {
        self.automorphism_keys.len()
    }

    /// Returns the decomposition basis used by every automorphism key.
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        self.first_automorphism_key().basis()
    }

    /// Evaluates the full trace and overwrites `output` with an encryption of
    /// `N` times the constant coefficient of the input phase.
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
        workspace: &mut NttGlweTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.apply_partial_to(input, 1, output, modulus, ntt, workspace);
    }

    /// Returns the first key, which exists because supported GLWE polynomial
    /// lengths are at least two.
    pub(super) fn first_automorphism_key(&self) -> &NttGlweAutomorphismKey<T> {
        self.automorphism_keys
            .first()
            .expect("a trace key must contain at least one automorphism key")
    }
}
