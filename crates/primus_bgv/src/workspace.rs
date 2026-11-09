use crate::BgvParameters;
use primus_poly::DcrtPolynomial;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Reusable full phase and one coefficient's exact CRT reconstruction scratch.
/// Drop or explicit erasure preserves geometry while securely clearing contents.
pub(crate) struct BgvDecryptWorkspace {
    pub(crate) phase: DcrtPolynomial<Vec<u64>>,
    pub(crate) residues: Vec<u64>,
    pub(crate) value: Vec<u64>,
}
impl BgvDecryptWorkspace {
    /// Allocates exact full-ring phase, one residue vector and one CRT integer.
    #[must_use]
    pub(crate) fn new(parameters: &BgvParameters) -> Self {
        Self {
            phase: DcrtPolynomial::zero(parameters.size().rns_poly_len()),
            residues: vec![0; parameters.base_q().moduli_count()],
            value: vec![0; parameters.base_q().big_uint_value_len()],
        }
    }
}
impl Zeroize for BgvDecryptWorkspace {
    fn zeroize(&mut self) {
        self.phase.as_mut().iter_mut().zeroize();
        self.residues.iter_mut().zeroize();
        self.value.iter_mut().zeroize();
    }
}
impl ZeroizeOnDrop for BgvDecryptWorkspace {}
impl Drop for BgvDecryptWorkspace {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primus_distr::ErrorDistribution;
    use primus_glwe_rns::SecretKeyDistr;
    use primus_modulus::BarrettModulus;
    use primus_shape::PolyLength;
    #[test]
    fn erasure_keeps_complete_workspace_allocations() {
        let parameters = BgvParameters::try_with_error_distribution(
            PolyLength::new(32),
            BarrettModulus::new(17),
            &[BarrettModulus::new(5441)],
            SecretKeyDistr::SparseTernary,
            ErrorDistribution::CenteredBinomial { eta: 1 },
        )
        .unwrap();
        let mut workspace = BgvDecryptWorkspace::new(&parameters);
        let pointers = (
            workspace.phase.as_ref().as_ptr(),
            workspace.residues.as_ptr(),
            workspace.value.as_ptr(),
        );
        workspace.phase.as_mut().fill(23);
        workspace.residues.fill(42);
        workspace.value.fill(87);
        workspace.zeroize();
        assert!(
            workspace
                .phase
                .as_ref()
                .iter()
                .chain(&workspace.residues)
                .chain(&workspace.value)
                .all(|&x| x == 0)
        );
        assert_eq!(
            pointers,
            (
                workspace.phase.as_ref().as_ptr(),
                workspace.residues.as_ptr(),
                workspace.value.as_ptr()
            )
        );
    }
}
