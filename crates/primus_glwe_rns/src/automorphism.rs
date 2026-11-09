//! Numerical compatibility and scratch shared by CRT/DCRT automorphism bindings.

use primus_decompose::DecompositionBaseLog;
use primus_integer::FheUint;
use primus_lattice::{RnsGadgetSize, workspace::DcrtGlevMulWorkspace};
use primus_ntt::NttTable;
use primus_poly::CrtPolynomial;
use primus_reduce::FieldContext;

use crate::parameter::{validate_glwe_size, validate_moduli};
use crate::{CrtGlevParameters, DcrtGadgetDomain, RnsDomainError};

/// One numerical metadata record per standalone key or complete automorphism key set.
/// Ordered Q determines the product and big-integer limb width; together with
/// radix and retained levels it determines the signed gadget basis. Secret and
/// NTT representation identity cannot be inferred from these values.
#[derive(Clone)]
pub(crate) struct AutomorphismKeyMetadata<T: FheUint> {
    size: RnsGadgetSize,
    moduli: Box<[T]>,
    log_basis: DecompositionBaseLog,
}

impl<T: FheUint> AutomorphismKeyMetadata<T> {
    pub(crate) fn new<M, Table>(domain: &DcrtGadgetDomain<'_, T, M, Table>) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        Self {
            size: domain.size(),
            moduli: domain.parameters().cipher_moduli_value().into(),
            log_basis: domain.basis().log_basis(),
        }
    }

    /// Checks the complete numerical binding before allocating evaluator scratch.
    /// The constructors never accept individual key entries from another domain,
    /// so validating the set's single record also covers all its entries.
    pub(crate) fn validate<M, Table>(
        &self,
        domain: &DcrtGadgetDomain<'_, T, M, Table>,
    ) -> Result<(), RnsDomainError<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        validate_glwe_size(self.size.rns_glwe_size(), domain.size().rns_glwe_size())?;
        let expected = self.size.level_count().get();
        let actual = domain.size().level_count().get();
        if expected != actual {
            return Err(RnsDomainError::DecompositionLevelCountMismatch { expected, actual });
        }
        validate_moduli(
            self.moduli.iter().copied(),
            domain.parameters().cipher_moduli_value().iter().copied(),
        )?;
        if self.log_basis != domain.basis().log_basis() {
            return Err(RnsDomainError::DecompositionBaseLogMismatch {
                expected: self.log_basis.get(),
                actual: domain.basis().log_basis().get(),
            });
        }
        Ok(())
    }
}

/// Scratch allocated from the already bound domain. Each kernel overwrites it;
/// only the evaluator owns its compatibility contract.
pub(crate) struct AutomorphismWorkspace<T: FheUint> {
    auto_crt_poly: CrtPolynomial<Vec<T>>,
    glev_workspace: DcrtGlevMulWorkspace<T>,
}

impl<T: FheUint> AutomorphismWorkspace<T> {
    pub(crate) fn from_parameters<M>(parameters: &CrtGlevParameters<T, M>) -> Self
    where
        M: FieldContext<T>,
    {
        let size = parameters.size();
        let glwe_size = size.rns_glwe_size();
        let crt_poly_len = glwe_size.rns_poly_len();

        let auto_crt_poly = CrtPolynomial::zero(crt_poly_len);
        let glev_workspace = DcrtGlevMulWorkspace::new(size, parameters.base_q());

        Self {
            auto_crt_poly,
            glev_workspace,
        }
    }

    pub(crate) fn as_mut(&mut self) -> (&mut CrtPolynomial<Vec<T>>, &mut DcrtGlevMulWorkspace<T>) {
        (&mut self.auto_crt_poly, &mut self.glev_workspace)
    }
}
