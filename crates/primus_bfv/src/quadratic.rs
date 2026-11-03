use primus_data::{Data, DataMut};
use primus_poly::DcrtPolynomial;

/// Scaled native BFV tensor `[c0,c1,c2]` with phase `c0+c1*s+c2*s²`.
///
/// Each component has already undergone exact BFV `round(t*T/Q)` scaling.
/// This is a degree-two ciphertext under one secret, not rank-two GLWE.
/// An unscaled [`crate::BfvRawTensor`] cannot be passed to a relinearizer.
/// It must be relinearized before use with degree-one evaluators, switching,
/// automorphisms or recovery. Each component has the same modulus-major NTT
/// layout; the consuming operation establishes its complete geometry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BfvQuadraticCiphertext<C> {
    data: C,
}

impl<C: Data<Elem = u64>> BfvQuadraticCiphertext<C> {
    /// Wraps storage with the native degree-two interpretation.
    #[must_use]
    pub fn new(data: C) -> Self {
        Self { data }
    }

    /// Borrows storage without copying or changing its representation.
    #[must_use]
    pub fn as_view(&self) -> BfvQuadraticCiphertext<&[u64]> {
        BfvQuadraticCiphertext::new(self.as_ref())
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
    /// Allocates zeroed native tensor storage.
    #[must_use]
    pub fn zero(length: usize) -> Self {
        Self::new(vec![0; length])
    }
}

impl<C: DataMut<Elem = u64>> BfvQuadraticCiphertext<C> {
    /// Borrows mutable degree-two storage.
    #[must_use]
    pub fn as_mut_view(&mut self) -> BfvQuadraticCiphertext<&mut [u64]> {
        BfvQuadraticCiphertext::new(self.as_mut())
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
