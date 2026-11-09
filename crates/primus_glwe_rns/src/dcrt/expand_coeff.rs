use primus_data::DataMut;
use primus_factor::ShoupFactor;
use primus_integer::{AsInto, BigUint, FheUint};
use primus_ntt::{DcrtTable, MonomialNttTable, NttTable};
use primus_reduce::FieldContext;
use primus_rns::{RNSBase, ResidueFactors};
use rayon::prelude::*;

use crate::{CrtGlevParameters, DcrtGadgetDomain, DcrtGlweCiphertext, DcrtGlweSecretKey};

use super::automorphism::DcrtGlweAutoKeyData;
use super::trace::DcrtGlweTraceWorkspace;
use crate::automorphism::{AutomorphismKeyMetadata, AutomorphismWorkspace};
use crate::workspace_pool::WorkspacePool;

mod evaluator;
pub use evaluator::{DcrtGlweExpandCoeffEvaluator, DcrtGlweExpandCoeffParallelEvaluator};

#[derive(Clone)]
/// Automorphism keys used to expand DCRT GLWE coefficients into ciphertexts.
pub struct DcrtGlweExpandCoeffKey<T: FheUint> {
    metadata: AutomorphismKeyMetadata<T>,
    // All entries are generated here from the same domain; no foreign entry can
    // bypass the single metadata check at evaluator construction.
    auto_keys: Vec<DcrtGlweAutoKeyData<T>>,
    ntt_monomial_factors: Vec<Vec<ShoupFactor<T>>>,
    inv_count_residues_by_level: Vec<ResidueFactors<Vec<ShoupFactor<T>>>>,
}

impl<T: FheUint> DcrtGlweExpandCoeffKey<T> {
    /// Generates the automorphism keys required for coefficient expansion.
    ///
    /// # Panics
    /// Panics if secret layouts or ordered moduli do not match the domain.
    ///
    /// # Correctness
    /// The secret must use the domain table's NTT representation.
    #[must_use]
    pub fn new<M, Table, R>(
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        dcrt_sk: &DcrtGlweSecretKey<T>,
        rng: &mut R,
    ) -> Self
    where
        R: rand::Rng + rand::CryptoRng,
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let log_n = params.poly_length().log_n();
        let degrees = (1..=log_n).rev().map(|x| (1usize << x) + 1);
        let auto_keys = DcrtGlweAutoKeyData::generate_key_set(domain, degrees, dcrt_sk, rng);

        let ntt_monomial_factors = Self::precompute_monomial_factors(params, domain.table());
        let inv_count_residues_by_level =
            Self::precompute_inv_count_residues(params, domain.rns_base());

        Self {
            metadata: AutomorphismKeyMetadata::new(domain),
            auto_keys,
            ntt_monomial_factors,
            inv_count_residues_by_level,
        }
    }

    /// Caches X^(-2^i) in the domain's NTT order for each expansion level.
    fn precompute_monomial_factors<M, Table>(
        params: &CrtGlevParameters<T, M>,
        table: &DcrtTable<Table>,
    ) -> Vec<Vec<ShoupFactor<T>>>
    where
        M: FieldContext<T>,
        Table: MonomialNttTable<ValueT = T>,
    {
        let poly_length = params.poly_length().get();
        let rns_poly_len = params.rns_poly_len();
        let moduli = params.cipher_moduli_value();
        let twice_poly_length = poly_length * 2;
        let log_n = params.poly_length().log_n();

        (0..log_n)
            .map(|i| {
                let degree = twice_poly_length - (1 << i);
                let mut monomial_ntt = vec![T::ZERO; rns_poly_len];
                table.transform_coeff_one_monomial(degree, &mut monomial_ntt);
                monomial_ntt
                    .chunks_exact(poly_length)
                    .zip(moduli)
                    .flat_map(|(poly, &modulus)| {
                        poly.iter()
                            .map(move |&value| ShoupFactor::new(value, modulus))
                    })
                    .collect()
            })
            .collect()
    }

    /// Normalizes the tree by its leaf count, including the no-tree count of one.
    fn precompute_inv_count_residues<M>(
        params: &CrtGlevParameters<T, M>,
        rns_base: &RNSBase<T, M>,
    ) -> Vec<ResidueFactors<Vec<ShoupFactor<T>>>>
    where
        M: FieldContext<T>,
    {
        let big_uint_value_len = params.big_uint_value_len();
        let log_n = params.poly_length().log_n();

        (0..=log_n)
            .map(|log_count| {
                let count = 1usize << log_count;
                let mut n = vec![T::ZERO; big_uint_value_len];
                n[0] = count.as_into();
                let n_residue = rns_base.decompose(BigUint(&n));

                ResidueFactors(
                    n_residue
                        .iter()
                        .zip(rns_base.moduli())
                        .map(|(&n, m)| ShoupFactor::new(m.reduce_inv(n), m.value()))
                        .collect(),
                )
            })
            .collect()
    }

    /// Expands a validated power-of-two prefix with the bound serial scratch.
    /// Full and partial evaluators each check their output count before entering.
    /// Ciphertext layouts remain caller preconditions, diagnosed here in debug builds.
    /// Converts each output to a view only when visiting its node; no view list is allocated.
    fn expand_kernel_to<M, Table, B>(
        &self,
        ciphertext: DcrtGlweCiphertext<&[T]>,
        result: &mut [DcrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        workspace: &mut DcrtGlweTraceWorkspace<T>,
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
        let moduli_value = params.cipher_moduli_value();

        ciphertext.mul_factor_to(
            &self.inv_count_residues_by_level[log_d],
            &mut result[0],
            poly_length,
            params.rns_poly_len(),
            moduli_value,
        );

        let (dcrt_glwe, auto_workspace) = workspace.as_mut();
        for (i, (auto_key, factors)) in self
            .auto_keys
            .iter()
            .zip(&self.ntt_monomial_factors)
            .enumerate()
            .take(log_d)
        {
            let level_len = 1 << i;
            let (x, y) = result[..level_len * 2].split_at_mut(level_len);

            x.iter_mut().zip(y).for_each(|(a_0, b_0)| {
                Self::expand_pair_kernel(
                    a_0.as_mut_view(),
                    b_0.as_mut_view(),
                    auto_key,
                    factors,
                    domain,
                    dcrt_glwe.as_mut_view(),
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
        ciphertext: DcrtGlweCiphertext<&[T]>,
        result: &mut [DcrtGlweCiphertext<B>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        workspace_pool: &WorkspacePool<DcrtGlweTraceWorkspace<T>>,
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
        let moduli_value = params.cipher_moduli_value();

        ciphertext.mul_factor_to(
            &self.inv_count_residues_by_level[log_d],
            &mut result[0],
            poly_length,
            params.rns_poly_len(),
            moduli_value,
        );

        for (i, (auto_key, factors)) in self
            .auto_keys
            .iter()
            .zip(&self.ntt_monomial_factors)
            .enumerate()
            .take(log_d)
        {
            let level_len = 1 << i;
            let (x, y) = result[..level_len * 2].split_at_mut(level_len);

            x.par_iter_mut().zip(y.par_iter_mut()).for_each_init(
                || workspace_pool.acquire(),
                |guard, (a_0, b_0)| {
                    let (dcrt_glwe, auto_workspace) = guard.workspace_mut().as_mut();
                    Self::expand_pair_kernel(
                        a_0.as_mut_view(),
                        b_0.as_mut_view(),
                        auto_key,
                        factors,
                        domain,
                        dcrt_glwe.as_mut_view(),
                        auto_workspace,
                    );
                },
            );
        }
    }

    /// Splits one node with the automorphism and its precomputed NTT monomial.
    /// The butterfly updates `lhs` and overwrites `rhs` directly in the NTT domain.
    /// Serial and parallel traversal borrow nodes individually;
    /// operands, factors and scratch must match the complete domain layout/order.
    fn expand_pair_kernel<M, Table>(
        mut lhs: DcrtGlweCiphertext<&mut [T]>,
        mut rhs: DcrtGlweCiphertext<&mut [T]>,
        auto_key: &DcrtGlweAutoKeyData<T>,
        factors: &[ShoupFactor<T>],
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
        mut scratch: DcrtGlweCiphertext<&mut [T]>,
        auto_workspace: &mut AutomorphismWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        let params = domain.parameters();
        let poly_length = params.poly_length().get();

        auto_key.automorphism_kernel(lhs.as_view(), scratch.as_mut_view(), domain, auto_workspace);
        lhs.butterfly_mul_factor_to(
            &scratch,
            factors,
            &mut rhs,
            poly_length,
            params.cipher_moduli_value(),
        );
    }
}
