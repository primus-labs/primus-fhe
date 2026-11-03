use primus_data::{Data, DataMut};
use primus_glwe_rns::DcrtGlweCiphertext;
use primus_poly::DcrtPolynomial;

use crate::BfvParameters;

/// A rank-one BFV ciphertext in physical component order `[c0, c1]`.
///
/// Each component is one modulus-major DCRT polynomial. Its phase is
/// `c0 + c1*s`; this is distinct from raw GLWE's mask/body representation.
/// Complete geometry is checked by the consuming operation, so a container
/// alone establishes neither its Q basis nor its NTT evaluation convention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BfvCiphertext<C> {
    data: C,
}

impl<C: Data<Elem = u64>> BfvCiphertext<C> {
    /// Wraps storage carrying the BFV `[c0,c1]` interpretation.
    /// Operations validate its complete length against their bound parameters.
    #[must_use]
    pub fn new(data: C) -> Self {
        Self { data }
    }

    /// Borrows the physical `[c0,c1]` storage.
    #[must_use]
    pub fn as_view(&self) -> BfvCiphertext<&[u64]> {
        BfvCiphertext::new(self.as_ref())
    }

    /// Borrows both DCRT components, checking the full ciphertext length.
    ///
    /// # Panics
    /// Rejects storage other than exactly twice `rns_poly_len`.
    #[must_use]
    pub fn c0_c1(&self, rns_poly_len: usize) -> (DcrtPolynomial<&[u64]>, DcrtPolynomial<&[u64]>) {
        assert_eq!(
            self.as_ref().len(),
            rns_poly_len
                .checked_mul(2)
                .expect("BFV ciphertext length overflow"),
            "BFV ciphertext length mismatch"
        );
        let (c0, c1) = self.as_ref().split_at(rns_poly_len);
        (DcrtPolynomial(c0), DcrtPolynomial(c1))
    }

    /// Explicitly exports `[a=-c1,b=c0]` for a legacy raw-GLWE operation.
    ///
    /// This boundary copies and negates residues, allocating and transforming
    /// nothing. Ordinary BFV encryption and recovery never use this conversion.
    ///
    /// # Correctness
    /// Both buffers use the parameter Q basis and the same NTT convention.
    /// Canonical input residues and the same actual secret are required.
    ///
    /// # Panics
    /// Rejects either incorrect complete length before writing output.
    pub fn write_raw_glwe_to<B: DataMut<Elem = u64>>(
        &self,
        output: &mut DcrtGlweCiphertext<B>,
        parameters: &BfvParameters,
    ) {
        let length = parameters.size().rns_poly_len();
        let (c0, c1) = self.c0_c1(length);
        assert_eq!(
            output.as_ref().len(),
            parameters.size().rns_glwe_len(),
            "raw GLWE output length mismatch"
        );
        let (mut masks, mut body) = output.a_b_mut(length);
        c1.neg_to(
            &mut masks.next().expect("rank-one mask"),
            parameters.poly_length().get(),
            parameters.base_q().moduli(),
        );
        body.as_mut().copy_from_slice(c0.as_ref());
    }
}

impl BfvCiphertext<Vec<u64>> {
    /// Allocates zeroed `[c0,c1]` storage of the requested complete length.
    #[must_use]
    pub fn zero(length: usize) -> Self {
        Self::new(vec![0; length])
    }
}

impl<C: DataMut<Elem = u64>> BfvCiphertext<C> {
    /// Borrows mutable `[c0,c1]` storage.
    #[must_use]
    pub fn as_mut_view(&mut self) -> BfvCiphertext<&mut [u64]> {
        BfvCiphertext::new(self.as_mut())
    }

    /// Borrows both mutable DCRT components after checking their full length.
    ///
    /// # Panics
    /// Rejects storage other than exactly twice `rns_poly_len`.
    #[must_use]
    pub fn c0_c1_mut(
        &mut self,
        rns_poly_len: usize,
    ) -> (DcrtPolynomial<&mut [u64]>, DcrtPolynomial<&mut [u64]>) {
        assert_eq!(
            self.as_ref().len(),
            rns_poly_len
                .checked_mul(2)
                .expect("BFV ciphertext length overflow"),
            "BFV ciphertext length mismatch"
        );
        let (c0, c1) = self.as_mut().split_at_mut(rns_poly_len);
        (DcrtPolynomial(c0), DcrtPolynomial(c1))
    }

    /// Explicitly imports raw GLWE as `[c0=b,c1=-a]` without allocation or NTT.
    /// The representation and panic conditions are [`Self::write_raw_glwe_to`]'s.
    pub fn set_from_raw_glwe<A: Data<Elem = u64>>(
        &mut self,
        input: &DcrtGlweCiphertext<A>,
        parameters: &BfvParameters,
    ) {
        let length = parameters.size().rns_poly_len();
        assert_eq!(
            input.as_ref().len(),
            parameters.size().rns_glwe_len(),
            "raw GLWE input length mismatch"
        );
        let (mut masks, body) = input.a_b(length);
        let (mut c0, mut c1) = self.c0_c1_mut(length);
        c0.as_mut().copy_from_slice(body.as_ref());
        masks.next().expect("rank-one mask").neg_to(
            &mut c1,
            parameters.poly_length().get(),
            parameters.base_q().moduli(),
        );
    }
}

impl<C: Data<Elem = u64>> AsRef<[u64]> for BfvCiphertext<C> {
    fn as_ref(&self) -> &[u64] {
        self.data.as_slice()
    }
}

impl<C: DataMut<Elem = u64>> AsMut<[u64]> for BfvCiphertext<C> {
    fn as_mut(&mut self) -> &mut [u64] {
        self.data.as_mut_slice()
    }
}
