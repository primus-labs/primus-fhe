use primus_data::{Data, DataMut};
use primus_poly::DcrtPolynomial;

/// Scaled native BFV tensor `[c0,c1,c2]` with phase `c0+c1*s+c2*s²`.
///
/// Each component has undergone the selected ordinary BFV backend's scaling:
/// the exact backend uses `round(t*T/Q)` on its integer tensor, whereas
/// [`crate::evaluation::BfvMultiplicationBackend::HpsPOverQ`] uses one-sided P/Q scaling
/// before tensoring and exact `round(t*T/P)` afterward.
/// This is a degree-two ciphertext under one secret, not rank-two GLWE.
/// The unscaled integer tensor is private to the multiplication owner; only
/// this scaled stage can be supplied to a relinearizer.
/// It must be relinearized before use with degree-one evaluators, switching,
/// automorphisms or recovery. Each component has the same modulus-major NTT
/// layout; the consuming operation establishes its complete geometry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BfvQuadraticCiphertext<C> {
    data: C,
    binding: Option<crate::ciphertext::Binding>,
}

impl<C: Data<Elem = u64>> BfvQuadraticCiphertext<C> {
    /// Wraps explicit raw storage with the native degree-two interpretation.
    ///
    /// The caller attests the ordered Q, actual NTT, BFV scaling and secret;
    /// no local provenance is inferred. Normal multiplication outputs use
    /// [`crate::BfvContext::new_quadratic_ciphertext`].
    #[must_use]
    pub fn from_raw(data: C) -> Self {
        Self {
            data,
            binding: None,
        }
    }

    pub(crate) fn bound(data: C, context: &crate::BfvContext, level: usize) -> Self {
        Self {
            data,
            binding: Some(crate::ciphertext::Binding::new(context, level)),
        }
    }

    pub(crate) fn check_binding(&self, context: &crate::BfvContext, level: usize) {
        if let Some(binding) = &self.binding {
            binding.check(context, level);
        }
    }

    /// Borrows storage without copying or changing its representation.
    #[must_use]
    pub fn as_view(&self) -> BfvQuadraticCiphertext<&[u64]> {
        BfvQuadraticCiphertext {
            data: self.as_ref(),
            binding: self.binding.clone(),
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

impl BfvQuadraticCiphertext<Vec<u64>> {
    /// Allocates explicit unbound raw native tensor storage.
    #[must_use]
    pub fn zero_raw(length: usize) -> Self {
        Self::from_raw(vec![0; length])
    }
}

impl<C: DataMut<Elem = u64>> BfvQuadraticCiphertext<C> {
    /// Borrows mutable degree-two storage.
    #[must_use]
    pub fn as_mut_view(&mut self) -> BfvQuadraticCiphertext<&mut [u64]> {
        let binding = self.binding.clone();
        BfvQuadraticCiphertext {
            data: self.data.as_mut_slice(),
            binding,
        }
    }

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

impl<C: Data<Elem = u64>> AsRef<[u64]> for BfvQuadraticCiphertext<C> {
    fn as_ref(&self) -> &[u64] {
        self.data.as_slice()
    }
}

impl<C: DataMut<Elem = u64>> AsMut<[u64]> for BfvQuadraticCiphertext<C> {
    fn as_mut(&mut self) -> &mut [u64] {
        self.data.as_mut_slice()
    }
}

fn assert_length(actual: usize, length: usize) {
    assert_eq!(
        actual,
        length
            .checked_mul(3)
            .expect("BFV quadratic length overflow"),
        "BFV quadratic ciphertext length mismatch"
    );
}
