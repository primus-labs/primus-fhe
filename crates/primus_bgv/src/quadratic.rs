use crate::{BgvContext, binding::Binding};
use primus_data::{Data, DataMut};
use primus_poly::DcrtPolynomial;

/// Native BGV tensor `[c0,c1,c2]` with phase `c0+c1*s+c2*s²`.
///
/// This is a degree-two ciphertext under one secret, not rank-two GLWE.
/// It must be relinearized before use with degree-one evaluators, switching,
/// automorphisms or recovery. Each component has the same modulus-major NTT
/// layout. Context-created tensors retain their exact local owner and level;
/// explicit raw storage inherits the consuming operation's caller contracts.
/// Its message multiplier is propagated by tensor multiplication and retained
/// by relinearization; it need not equal that of another tensor at this level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BgvQuadraticCiphertext<C> {
    data: C,
    binding: Option<Binding>,
    correction_factor: u64,
}

impl<C: Data<Elem = u64>> BgvQuadraticCiphertext<C> {
    /// Wraps raw degree-two storage for explicit advanced interoperability.
    /// Declares correction factor one. The caller supplies its exact context,
    /// level, NTT convention and secret.
    #[must_use]
    pub fn from_raw(data: C) -> Self {
        Self {
            data,
            binding: None,
            correction_factor: 1,
        }
    }

    pub(crate) fn from_bound(data: C, context: &BgvContext, level: usize) -> Self {
        Self {
            data,
            binding: Some(Binding::new(context, level)),
            correction_factor: 1,
        }
    }

    /// Returns the canonical plaintext message multiplier of this tensor.
    #[must_use]
    pub fn correction_factor(&self) -> u64 {
        self.correction_factor
    }

    pub(crate) fn set_correction_factor(&mut self, factor: u64) {
        self.correction_factor = factor;
    }

    pub(crate) fn check_binding(&self, context: &BgvContext, level: usize) {
        if let Some(binding) = &self.binding {
            binding.check(context, level);
        }
    }

    /// Borrows storage without copying or changing its representation.
    #[must_use]
    pub fn as_view(&self) -> BgvQuadraticCiphertext<&[u64]> {
        BgvQuadraticCiphertext {
            data: self.as_ref(),
            binding: self.binding.clone(),
            correction_factor: self.correction_factor,
        }
    }

    /// Borrows all three complete DCRT components.
    ///
    /// # Panics
    /// Rejects storage other than exactly `3*rns_poly_len`.
    #[must_use]
    #[allow(clippy::type_complexity)] // The three physical components are the return value.
    pub fn c0_c1_c2(
        &self,
        rns_poly_len: usize,
    ) -> (
        DcrtPolynomial<&[u64]>,
        DcrtPolynomial<&[u64]>,
        DcrtPolynomial<&[u64]>,
    ) {
        assert_length(self.as_ref().len(), rns_poly_len);
        let (c0, rest) = self.as_ref().split_at(rns_poly_len);
        let (c1, c2) = rest.split_at(rns_poly_len);
        (DcrtPolynomial(c0), DcrtPolynomial(c1), DcrtPolynomial(c2))
    }
}

impl BgvQuadraticCiphertext<Vec<u64>> {
    /// Allocates raw zeroed tensor storage without context or level provenance.
    #[must_use]
    pub fn zero_raw(length: usize) -> Self {
        Self::from_raw(vec![0; length])
    }
}

impl<C: DataMut<Elem = u64>> BgvQuadraticCiphertext<C> {
    /// Borrows three mutable components after checking the complete length.
    ///
    /// # Panics
    /// Rejects storage other than exactly `3*rns_poly_len`.
    #[must_use]
    #[allow(clippy::type_complexity)] // Keep the mutable component interface symmetric.
    pub fn c0_c1_c2_mut(
        &mut self,
        rns_poly_len: usize,
    ) -> (
        DcrtPolynomial<&mut [u64]>,
        DcrtPolynomial<&mut [u64]>,
        DcrtPolynomial<&mut [u64]>,
    ) {
        assert_length(self.as_ref().len(), rns_poly_len);
        let (c0, rest) = self.as_mut().split_at_mut(rns_poly_len);
        let (c1, c2) = rest.split_at_mut(rns_poly_len);
        (DcrtPolynomial(c0), DcrtPolynomial(c1), DcrtPolynomial(c2))
    }
}

impl<C: Data<Elem = u64>> AsRef<[u64]> for BgvQuadraticCiphertext<C> {
    fn as_ref(&self) -> &[u64] {
        self.data.as_slice()
    }
}

impl<C: DataMut<Elem = u64>> AsMut<[u64]> for BgvQuadraticCiphertext<C> {
    fn as_mut(&mut self) -> &mut [u64] {
        self.data.as_mut_slice()
    }
}

fn assert_length(actual: usize, length: usize) {
    assert_eq!(
        actual,
        length
            .checked_mul(3)
            .expect("BGV quadratic length overflow"),
        "BGV quadratic ciphertext length mismatch"
    );
}
