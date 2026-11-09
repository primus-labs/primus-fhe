use primus_data::{Data, DataMut};
use primus_factor::ShoupFactor;
use primus_integer::{AsInto, BigUint, FheUint};
use primus_ntt::NttTable;
use primus_reduce::FieldContext;
use primus_rns::ResidueFactors;
use rayon::prelude::*;

use crate::{CrtGlweCiphertext, DcrtGadgetDomain, DcrtGlweSecretKey, GlweSecretKey};

use super::automorphism::CrtGlweAutoKeyData;
use super::trace::CrtGlweTraceWorkspace;
use crate::automorphism::{AutomorphismKeyMetadata, AutomorphismWorkspace};
use crate::workspace_pool::WorkspacePool;

mod evaluator;
pub use evaluator::{CrtGlweExpandCoeffEvaluator, CrtGlweExpandCoeffParallelEvaluator};

#[derive(Clone)]
/// Automorphism keys used to expand CRT GLWE coefficients into ciphertexts.
pub struct CrtGlweExpandCoeffKey<T: FheUint> {
    metadata: AutomorphismKeyMetadata<T>,
    // All entries are generated here from the same domain; no foreign entry can
    // bypass the single metadata check at evaluator construction.
    auto_keys: Vec<CrtGlweAutoKeyData<T>>,
    inv_count_residues_by_level: Vec<ResidueFactors<Vec<ShoupFactor<T>>>>,
}

impl<T: FheUint> CrtGlweExpandCoeffKey<T> {
    /// Generates the automorphism keys required for coefficient expansion.
    ///
    /// # Panics
    /// Panics if secret layouts or ordered moduli do not match the domain.
    ///
    /// # Correctness
    /// Both secret representations must describe the same key, with the DCRT
    /// secret using the domain table's NTT representation.
    #[must_use]
    pub fn new<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        sk: &GlweSecretKey<T>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let log_n = params.poly_length().log_n();
        let degrees = (1..=log_n).rev().map(|x| (1usize << x) + 1);
        let auto_keys = CrtGlweAutoKeyData::generate_key_set(domain, degrees, sk, dcrt_sk, rng);

        let base_q = params.base_q();

        let inv_count_residues_by_level = (0..=log_n)
            .map(|log_count| {
                let count = 1usize << log_count;
                let n = count.as_into();
                let n_residue = base_q.decompose(BigUint(&[n]));

                ResidueFactors(
                    n_residue
                        .iter()
                        .zip(base_q.moduli())
                        .map(|(&n, m)| ShoupFactor::new(m.reduce_inv(n), m.value()))
                        .collect(),
                )
            })
            .collect();

        Self {
            metadata: AutomorphismKeyMetadata::new(domain),
            auto_keys,
            inv_count_residues_by_level,
        }
    }

    /// Expands a validated count with the bound serial scratch.
    /// Non-power-of-two counts require the supported-prefix plaintext condition.
    /// Public evaluators validate counts and complete ciphertext layouts once.
    /// Converts each output to a view only when visiting its node; no view list is allocated.
    fn expand_kernel_to<M, Table, B>(
        &self,
        ciphertext: CrtGlweCiphertext<&[T]>,
        result: &mut [CrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        workspace: &mut CrtGlweTraceWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        B: DataMut<Elem = T>,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length().get();
        let count = result.len();

        let log_d = count.next_power_of_two().trailing_zeros() as usize;
        let rns_poly_len = params.rns_poly_len();

        ciphertext.mul_factor_to(
            &self.inv_count_residues_by_level[log_d],
            &mut result[0],
            poly_length,
            rns_poly_len,
            params.cipher_moduli_value(),
        );

        let (crt_glwe, auto_workspace) = workspace.as_mut();
        for (i, auto_key) in self.auto_keys.iter().enumerate().take(log_d) {
            let level_len = 1 << i;
            let end = (level_len * 2).min(count);
            let (lower, upper) = result[..end].split_at_mut(level_len);
            let (paired, constant) = lower.split_at_mut(upper.len());
            let monomial_degree = poly_length * 2 - level_len;

            paired.iter_mut().zip(upper).for_each(|(a_0, b_0)| {
                Self::expand_pair_kernel(
                    a_0.as_mut_view(),
                    b_0.as_mut_view(),
                    auto_key,
                    monomial_degree,
                    domain,
                    crt_glwe.as_mut_view(),
                    auto_workspace,
                );
            });
            // Only the final level can have unpaired leaves. Their plaintext
            // support is already constant; double to finish B=next_pow2(k)
            // normalization without introducing another key-switch error.
            for leaf in constant {
                Self::double_leaf_kernel(leaf, domain);
            }
        }
    }

    /// Parallel traversal of the same expansion tree. Each task exclusively owns
    /// a preallocated workspace guard, which returns scratch on completion or unwind.
    /// Output-count and ciphertext-layout preconditions match the serial kernel.
    fn expand_parallel_kernel_to<M, Table, B>(
        &self,
        ciphertext: CrtGlweCiphertext<&[T]>,
        result: &mut [CrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        workspace_pool: &WorkspacePool<CrtGlweTraceWorkspace<T>>,
    ) where
        M: FieldContext<T> + Sync,
        B: DataMut<Elem = T> + Send,
        Table: NttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length().get();
        let count = result.len();

        let log_d = count.next_power_of_two().trailing_zeros() as usize;
        let rns_poly_len = params.rns_poly_len();

        ciphertext.mul_factor_to(
            &self.inv_count_residues_by_level[log_d],
            &mut result[0],
            poly_length,
            rns_poly_len,
            params.cipher_moduli_value(),
        );

        for (i, auto_key) in self.auto_keys.iter().enumerate().take(log_d) {
            let level_len = 1 << i;
            let end = (level_len * 2).min(count);
            let (lower, upper) = result[..end].split_at_mut(level_len);
            let (paired, constant) = lower.split_at_mut(upper.len());
            let monomial_degree = poly_length * 2 - level_len;

            let chunk_size = paired.len().div_ceil(workspace_pool.capacity());
            paired
                .par_chunks_mut(chunk_size)
                .zip(upper.par_chunks_mut(chunk_size))
                .for_each(|(left, right)| {
                    let mut guard = workspace_pool.acquire();
                    let (crt_glwe, auto_workspace) = guard.workspace_mut().as_mut();
                    for (a_0, b_0) in left.iter_mut().zip(right) {
                        Self::expand_pair_kernel(
                            a_0.as_mut_view(),
                            b_0.as_mut_view(),
                            auto_key,
                            monomial_degree,
                            domain,
                            crt_glwe.as_mut_view(),
                            auto_workspace,
                        );
                    }
                });
            // Only the final level can have unpaired leaves. Their plaintext
            // support is already constant; double to finish B=next_pow2(k)
            // normalization without introducing another key-switch error.
            for leaf in constant {
                Self::double_leaf_kernel(leaf, domain);
            }
        }
    }

    /// Splits the original node `c` into `lhs = c + auto(c)` and
    /// `rhs = X^degree * (c - auto(c))`.
    /// Serial and parallel traversal borrow each output separately, avoiding an
    /// allocated collection of views. Operands and scratch must have the complete
    /// domain layout; `scratch` and the automorphism workspace are overwritten.
    fn expand_pair_kernel<M, Table>(
        mut lhs: CrtGlweCiphertext<&mut [T]>,
        mut rhs: CrtGlweCiphertext<&mut [T]>,
        auto_key: &CrtGlweAutoKeyData<T>,
        monomial_degree: usize,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        mut scratch: CrtGlweCiphertext<&mut [T]>,
        auto_workspace: &mut AutomorphismWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length().get();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli();

        auto_key.automorphism_kernel(lhs.as_view(), scratch.as_mut_view(), domain, auto_workspace);
        lhs.sub_to(&scratch, &mut rhs, poly_length, rns_poly_len, moduli);
        rhs.mul_monomial_assign(monomial_degree, poly_length, rns_poly_len, moduli);
        lhs.add_assign(&scratch, poly_length, rns_poly_len, moduli);
    }

    fn double_leaf_kernel<M, Table, B>(
        leaf: &mut CrtGlweCiphertext<B>,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        B: DataMut<Elem = T>,
    {
        let parameters = domain.parameters();
        for mut polynomial in leaf.iter_crt_poly_mut(parameters.rns_poly_len()) {
            for (limb, &modulus) in polynomial
                .iter_each_modulus_mut(parameters.poly_length().get())
                .zip(parameters.cipher_moduli())
            {
                modulus.reduce_double_slice_assign(limb);
            }
        }
    }
}

/// Validate the entire batch before normalization can write its first output.
fn assert_expansion_layout<T: FheUint, B: Data<Elem = T>>(
    input_length: usize,
    output: &[CrtGlweCiphertext<B>],
    expected_length: usize,
) {
    assert_eq!(
        input_length, expected_length,
        "expansion input layout mismatch"
    );
    assert!(
        output
            .iter()
            .all(|ciphertext| ciphertext.as_ref().len() == expected_length),
        "expansion output layout mismatch",
    );
}
