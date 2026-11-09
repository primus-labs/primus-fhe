//! Reusable p-preserving Radix and Hybrid gadget product scratch.
use primus_lattice::{
    glev::DcrtGlev,
    glwe::DcrtGlwe,
    hybrid::{HybridModDown, NativeHybridProduct},
    radix::NativeRadixParameters,
    workspace::DcrtGlevMulWorkspace,
};
use primus_ntt::{NttAutomorphismPermutation, NttTable};
use primus_poly::{CrtPolynomial, DcrtPolynomial};
use primus_reduce::ReduceInv;

use crate::BgvContext;

use super::{BgvEvaluationKeyError, backend::NativeEvaluationBasis, material::NativeEvaluationKey};

/// Prepared native p-preserving product. The low-level GLev kernel is only a
/// componentwise linear sum: its temporary views do not invoke raw b-a*s phase,
/// mask/body combination, or a ciphertext sign conversion.
enum ProductWorkspace<'a> {
    Radix {
        parameters: &'a NativeRadixParameters,
        p_inverse: Vec<u64>,
        workspace: DcrtGlevMulWorkspace<u64>,
    },
    Hybrid(NativeHybridProduct<'a>),
}
pub(super) struct NativeGadgetProduct<'a> {
    pub(super) context: &'a BgvContext,
    pub(super) key: &'a NativeEvaluationKey,
    pub(super) coefficient: Vec<u64>,
    workspace: ProductWorkspace<'a>,
}
impl<'a> NativeGadgetProduct<'a> {
    pub(super) fn try_new(
        context: &'a BgvContext,
        key: &'a NativeEvaluationKey,
    ) -> Result<Self, BgvEvaluationKeyError> {
        key.validate(context)?;
        let workspace = match &key.basis {
            NativeEvaluationBasis::Radix(parameters) => {
                let base = parameters.base_q();
                ProductWorkspace::Radix {
                    parameters,
                    p_inverse: base.moduli().iter().map(|q| q.reduce_inv(key.p)).collect(),
                    workspace: DcrtGlevMulWorkspace::new(parameters.size(), base),
                }
            }
            NativeEvaluationBasis::Hybrid(parameters) => {
                ProductWorkspace::Hybrid(NativeHybridProduct::try_new(
                    parameters,
                    context.table(),
                    HybridModDown::PlaintextPreserving(key.p),
                )?)
            }
        };
        Ok(Self {
            context,
            key,
            coefficient: vec![0; context.rns_poly_len(key.level)],
            workspace,
        })
    }
    pub(super) fn poly_len(&self) -> usize {
        self.coefficient.len()
    }
    pub(super) fn product_to(
        &mut self,
        input: &[u64],
        permutation: Option<&NttAutomorphismPermutation>,
        output: &mut [u64],
    ) {
        if permutation.is_none()
            && let ProductWorkspace::Hybrid(product) = &mut self.workspace
        {
            product.product_to(input, &self.key.columns, output);
            return;
        }
        let n = self.key.n;
        if let Some(permutation) = permutation {
            for (input, output) in input
                .chunks_exact(n)
                .zip(self.coefficient.chunks_exact_mut(n))
            {
                permutation.apply_to(input, output);
            }
        } else {
            self.coefficient.copy_from_slice(input);
        }
        match &mut self.workspace {
            ProductWorkspace::Radix {
                parameters,
                p_inverse,
                workspace,
            } => {
                let base = parameters.base_q();
                DcrtPolynomial(self.coefficient.as_mut_slice()).mul_scalar_assign(
                    p_inverse,
                    n,
                    base.moduli(),
                );
                for (table, limb) in self
                    .context
                    .table()
                    .iter()
                    .zip(self.coefficient.chunks_exact_mut(n))
                {
                    table.inverse_transform_slice(limb);
                }
                DcrtGlev(self.key.columns.as_slice()).mul_crt_polynomial_to(
                    &CrtPolynomial(self.coefficient.as_slice()),
                    &mut DcrtGlwe(output),
                    parameters.basis(),
                    self.context.table(),
                    base,
                    workspace,
                );
            }
            ProductWorkspace::Hybrid(product) => {
                product.product_to(&self.coefficient, &self.key.columns, output)
            }
        }
    }
}
