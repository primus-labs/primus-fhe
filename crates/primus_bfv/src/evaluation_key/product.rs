//! One reusable native gadget product in the evaluation key's Q prefix.
use primus_lattice::{
    glev::DcrtGlev,
    glwe::DcrtGlwe,
    hybrid::{HybridModDown, NativeHybridProduct},
    workspace::DcrtGlevMulWorkspace,
};
use primus_ntt::{NttAutomorphismPermutation, NttTable};
use primus_poly::CrtPolynomial;

use crate::BfvContext;

use super::{BfvEvaluationKeyError, backend::NativeEvaluationBasis, material::NativeEvaluationKey};

/// Prepared native product. The radix GLev kernel is only a
/// componentwise linear sum: its temporary views do not invoke raw b-a*s phase,
/// mask/body combination, or a ciphertext sign conversion.
pub(super) struct NativeGadgetProduct<'a> {
    pub(super) context: &'a BfvContext,
    pub(super) coefficient: Vec<u64>,
    workspace: NativeProductWorkspace<'a>,
}

enum NativeProductWorkspace<'a> {
    Radix(DcrtGlevMulWorkspace<u64>),
    Hybrid(NativeHybridProduct<'a>),
}

impl<'a> NativeGadgetProduct<'a> {
    // The key's generating context has already been established. The scratch
    // belongs to the product, while the caller keeps the key (owned or borrowed).
    pub(super) fn try_from_validated_key(
        context: &'a BfvContext,
        key: &NativeEvaluationKey,
    ) -> Result<Self, BfvEvaluationKeyError> {
        let workspace = match &key.basis {
            NativeEvaluationBasis::Radix(parameters) => NativeProductWorkspace::Radix(
                DcrtGlevMulWorkspace::new(parameters.size(), parameters.base_q()),
            ),
            NativeEvaluationBasis::Hybrid(parameters) => NativeProductWorkspace::Hybrid(
                NativeHybridProduct::try_new(parameters, context.table(), HybridModDown::Centered)?,
            ),
        };
        Ok(Self {
            context,
            coefficient: vec![0; context.rns_poly_len(key.level)],
            workspace,
        })
    }

    pub(super) fn poly_len(&self) -> usize {
        self.coefficient.len()
    }

    pub(super) fn product_to(
        &mut self,
        key: &NativeEvaluationKey,
        input: &[u64],
        permutation: Option<&NttAutomorphismPermutation>,
        output: &mut [u64],
    ) {
        if permutation.is_none()
            && let NativeProductWorkspace::Hybrid(product) = &mut self.workspace
        {
            product.product_to(input, &key.columns, output);
            return;
        }
        let n = key.n;
        let coefficient = &mut self.coefficient;
        if let Some(permutation) = permutation {
            for (input, output) in input.chunks_exact(n).zip(coefficient.chunks_exact_mut(n)) {
                permutation.apply_to(input, output);
            }
        } else {
            coefficient.copy_from_slice(input);
        }
        match (&key.basis, &mut self.workspace) {
            (
                NativeEvaluationBasis::Radix(parameters),
                NativeProductWorkspace::Radix(workspace),
            ) => {
                let table = self.context.table();
                for (table, limb) in table.iter().zip(coefficient.chunks_exact_mut(n)) {
                    table.inverse_transform_slice(limb);
                }
                DcrtGlev(key.columns.as_slice()).mul_crt_polynomial_to(
                    &CrtPolynomial(&*coefficient),
                    &mut DcrtGlwe(output),
                    parameters.basis(),
                    table,
                    parameters.base_q(),
                    workspace,
                );
            }
            (NativeEvaluationBasis::Hybrid(_), NativeProductWorkspace::Hybrid(product)) => {
                product.product_to(coefficient, &key.columns, output);
            }
            _ => unreachable!("prepared native BFV workspace backend"),
        }
    }
}
