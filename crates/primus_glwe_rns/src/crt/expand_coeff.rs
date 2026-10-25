use primus_data::DataMut;
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

    /// Expands a validated power-of-two prefix with the bound serial scratch.
    /// Full and partial evaluators each check their output count before entering.
    /// Ciphertext layouts remain caller preconditions, diagnosed here in debug builds.
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
        let len = params.rns_glwe_len();
        debug_assert_eq!(ciphertext.as_ref().len(), len);
        debug_assert!(
            result
                .iter()
                .all(|ciphertext| ciphertext.as_ref().len() == len)
        );

        let poly_length = params.poly_length().get();
        let count = result.len();

        let log_d = count.trailing_zeros() as usize;
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
            let (x, y) = result[..level_len * 2].split_at_mut(level_len);
            let monomial_degree = poly_length * 2 - level_len;

            x.iter_mut().zip(y).for_each(|(a_0, b_0)| {
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
        let len = params.rns_glwe_len();
        debug_assert_eq!(ciphertext.as_ref().len(), len);
        debug_assert!(
            result
                .iter()
                .all(|ciphertext| ciphertext.as_ref().len() == len)
        );

        let poly_length = params.poly_length().get();
        let count = result.len();

        let log_d = count.trailing_zeros() as usize;
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
            let (x, y) = result[..level_len * 2].split_at_mut(level_len);
            let monomial_degree = poly_length * 2 - level_len;

            x.par_iter_mut().zip(y.par_iter_mut()).for_each_init(
                || workspace_pool.acquire(),
                |guard, (a_0, b_0)| {
                    let (crt_glwe, auto_workspace) = guard.workspace_mut().as_mut();
                    Self::expand_pair_kernel(
                        a_0.as_mut_view(),
                        b_0.as_mut_view(),
                        auto_key,
                        monomial_degree,
                        domain,
                        crt_glwe.as_mut_view(),
                        auto_workspace,
                    );
                },
            );
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
}
