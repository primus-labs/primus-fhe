//! Numerical compatibility and scratch shared by CRT/DCRT automorphism bindings.

use primus_decompose::DecompositionBaseLog;
use primus_integer::FheUint;
use primus_lattice::{RnsGadgetSize, workspace::DcrtGlevMulWorkspace};
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::CrtPolynomial;
use primus_reduce::FieldContext;

use crate::parameter::{validate_dcrt_table, validate_glwe_size, validate_moduli};
use crate::{CrtGlevParameters, RnsDomainError};

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
    pub(crate) fn new<M>(parameters: &CrtGlevParameters<T, M>) -> Self
    where
        M: FieldContext<T>,
    {
        Self {
            size: parameters.size(),
            moduli: parameters.cipher_moduli_value().into(),
            log_basis: parameters.basis().log_basis(),
        }
    }

    /// Checks the complete numerical binding before allocating evaluator scratch.
    /// The constructors never accept individual key entries with different parameters,
    /// so validating the set's single record also covers all its entries.
    pub(crate) fn validate<M, Table>(
        &self,
        parameters: &CrtGlevParameters<T, M>,
        table: &DcrtTable<Table>,
    ) -> Result<(), RnsDomainError<T>>
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
    {
        validate_dcrt_table(parameters.poly_length(), parameters.cipher_moduli(), table)?;
        validate_glwe_size(self.size.rns_glwe_size(), parameters.size().rns_glwe_size())?;
        let expected = self.size.level_count().get();
        let actual = parameters.size().level_count().get();
        if expected != actual {
            return Err(RnsDomainError::DecompositionLevelCountMismatch { expected, actual });
        }
        validate_moduli(
            self.moduli.iter().copied(),
            parameters.cipher_moduli_value().iter().copied(),
        )?;
        if self.log_basis != parameters.basis().log_basis() {
            return Err(RnsDomainError::DecompositionBaseLogMismatch {
                expected: self.log_basis.get(),
                actual: parameters.basis().log_basis().get(),
            });
        }
        Ok(())
    }
}

/// Scratch allocated from the already bound parameters. Each kernel overwrites it;
/// only the evaluator owns its compatibility contract.
pub(crate) struct AutomorphismWorkspace<T: FheUint> {
    polynomial: CrtPolynomial<Vec<T>>,
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

        let polynomial = CrtPolynomial::zero(crt_poly_len);
        let glev_workspace = DcrtGlevMulWorkspace::new(size, parameters.base_q());

        Self {
            polynomial,
            glev_workspace,
        }
    }

    pub(crate) fn as_mut(&mut self) -> (&mut CrtPolynomial<Vec<T>>, &mut DcrtGlevMulWorkspace<T>) {
        (&mut self.polynomial, &mut self.glev_workspace)
    }
}
