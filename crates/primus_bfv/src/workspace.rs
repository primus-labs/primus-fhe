use primus_lattice::RnsGlweSize;
use primus_poly::DcrtPolynomial;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::BfvParameters;

/// Reusable phase and codec-conversion buffers for BFV recovery.
///
/// Each decryption overwrites both buffers. Drop and explicit [`Zeroize::zeroize`]
/// erase their contents; explicit erasure preserves lengths and allocations.
pub struct BfvDecryptWorkspace {
    size: RnsGlweSize,
    phase: DcrtPolynomial<Vec<u64>>,
    conversion: Vec<u64>,
}

impl BfvDecryptWorkspace {
    /// Allocates exactly one phase and the codec's required conversion scratch.
    #[must_use]
    pub fn new(parameters: &BfvParameters) -> Self {
        Self {
            size: parameters.size(),
            phase: DcrtPolynomial::zero(parameters.size().rns_poly_len()),
            conversion: vec![
                0;
                parameters
                    .codec()
                    .decode_scratch_len(parameters.poly_length().get())
            ],
        }
    }

    /// Returns the retained geometry; basis identity is established by context.
    #[must_use]
    pub(crate) fn size(&self) -> RnsGlweSize {
        self.size
    }

    pub(crate) fn as_mut(&mut self) -> (&mut DcrtPolynomial<Vec<u64>>, &mut [u64]) {
        (&mut self.phase, &mut self.conversion)
    }
}

impl Zeroize for BfvDecryptWorkspace {
    fn zeroize(&mut self) {
        self.phase.as_mut().iter_mut().zeroize();
        self.conversion.iter_mut().zeroize();
    }
}

impl ZeroizeOnDrop for BfvDecryptWorkspace {}

impl Drop for BfvDecryptWorkspace {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primus_glwe_rns::SecretKeyDistr;
    use primus_modulus::BarrettModulus;
    use primus_shape::PolyLength;

    #[test]
    fn explicit_erasure_preserves_both_allocations_and_geometry() {
        for count in [1, 2] {
            let moduli = [65_537, 114_689].map(BarrettModulus::new);
            let parameters = BfvParameters::try_new(
                PolyLength::new(32),
                BarrettModulus::new(17),
                BarrettModulus::new(257),
                &moduli[..count],
                SecretKeyDistr::SparseTernary,
                1.0,
            )
            .unwrap();
            let mut workspace = BfvDecryptWorkspace::new(&parameters);
            workspace.phase.as_mut().fill(0xfeed);
            workspace.conversion.fill(0xbeef);
            let phase_pointer = workspace.phase.as_ref().as_ptr();
            let conversion_pointer = workspace.conversion.as_ptr();
            let conversion_length = workspace.conversion.len();
            workspace.zeroize();
            assert_eq!(workspace.size(), parameters.size());
            assert_eq!(
                workspace.phase.as_ref(),
                vec![0; parameters.size().rns_poly_len()]
            );
            assert_eq!(workspace.conversion, vec![0; conversion_length]);
            assert_eq!(workspace.phase.as_ref().as_ptr(), phase_pointer);
            assert_eq!(workspace.conversion.as_ptr(), conversion_pointer);
        }
    }
}
