use primus_data::{Data, DataMut};
use primus_glwe_rns::DcrtGlweCiphertext;
use primus_poly::DcrtPolynomial;

use crate::BfvParameters;

/// Rejected raw-storage adoption or local context/level provenance.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BfvCiphertextBindingError {
    /// Bound storage was created by a different context owner.
    #[error("BFV context provenance mismatch")]
    ContextMismatch,
    /// The requested level was not prepared.
    #[error("BFV level {requested} is outside {available} prepared levels")]
    Level {
        /// Requested prefix level.
        requested: usize,
        /// Number of prepared prefix levels.
        available: usize,
    },
    /// Bound storage has another immutable level.
    #[error("BFV ciphertext level mismatch: expected {expected}, got {actual}")]
    BoundLevel {
        /// Level requested by the consuming operation.
        expected: usize,
        /// Level stored with the ciphertext.
        actual: usize,
    },
    /// Complete physical ciphertext length differs.
    #[error("BFV ciphertext length mismatch: expected {expected}, got {actual}")]
    Length {
        /// Required word count.
        expected: usize,
        /// Supplied word count.
        actual: usize,
    },
    /// A raw residue is not canonical for its ordered modulus limb.
    #[error("BFV residue {value} at word {index} is not below {modulus}")]
    NonCanonical {
        /// Physical word index in component-major, modulus-major order.
        index: usize,
        /// Supplied residue.
        value: u64,
        /// Required exclusive modulus bound.
        modulus: u64,
    },
}

// A local construction claim, not a proof of the actual secret or payload.
#[derive(Clone, Debug)]
pub(crate) struct Binding {
    context: std::sync::Arc<()>,
    pub(crate) level: usize,
}
impl Binding {
    pub(crate) fn new(context: &crate::BfvContext, level: usize) -> Self {
        Self {
            context: std::sync::Arc::clone(context.identity()),
            level,
        }
    }
    pub(crate) fn validate(
        &self,
        context: &crate::BfvContext,
        level: usize,
    ) -> Result<(), BfvCiphertextBindingError> {
        if !std::sync::Arc::ptr_eq(&self.context, context.identity()) {
            return Err(BfvCiphertextBindingError::ContextMismatch);
        }
        if self.level != level {
            return Err(BfvCiphertextBindingError::BoundLevel {
                expected: level,
                actual: self.level,
            });
        }
        Ok(())
    }
    pub(crate) fn check(&self, context: &crate::BfvContext, level: usize) {
        self.validate(context, level)
            .expect("BFV ciphertext binding mismatch");
    }
}
impl PartialEq for Binding {
    fn eq(&self, other: &Self) -> bool {
        self.level == other.level && std::sync::Arc::ptr_eq(&self.context, &other.context)
    }
}
impl Eq for Binding {}

/// A rank-one BFV ciphertext in physical component order `[c0, c1]`.
///
/// Each component is one modulus-major DCRT polynomial. Its phase is
/// `c0 + c1*s`; this is distinct from raw GLWE's mask/body representation.
/// Context allocation records immutable local context/level provenance. Raw
/// storage explicitly constructed with [`Self::from_raw`] instead retains the
/// caller's ordered Q, actual NTT and secret contracts; metadata proves none of
/// those mathematical facts about arbitrary imported words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BfvCiphertext<C> {
    data: C,
    pub(crate) binding: Option<crate::ciphertext::Binding>,
}

impl<C: Data<Elem = u64>> BfvCiphertext<C> {
    /// Wraps explicit raw storage carrying the BFV `[c0,c1]` interpretation.
    ///
    /// No context or level is inferred. A consuming operation checks geometry;
    /// the caller attests its ordered basis, actual NTT, scale and secret. Use
    /// [`crate::BfvContext::new_ciphertext`] for normal bound output storage.
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

    pub(crate) fn validate_binding(
        &self,
        context: &crate::BfvContext,
        level: usize,
    ) -> Result<(), BfvCiphertextBindingError> {
        self.binding
            .as_ref()
            .map_or(Ok(()), |binding| binding.validate(context, level))
    }
    pub(crate) fn check_binding(&self, context: &crate::BfvContext, level: usize) {
        self.validate_binding(context, level)
            .expect("BFV ciphertext binding mismatch");
    }

    pub(crate) fn bound_level(&self, context: &crate::BfvContext) -> usize {
        let binding = self
            .binding
            .as_ref()
            .expect("raw BFV storage needs explicit level recovery");
        binding.check(context, binding.level);
        binding.level
    }

    /// Borrows the physical `[c0,c1]` storage.
    #[must_use]
    pub fn as_view(&self) -> BfvCiphertext<&[u64]> {
        BfvCiphertext {
            data: self.as_ref(),
            binding: self.binding.clone(),
        }
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
    /// Allocates explicit unbound raw `[c0,c1]` storage of the complete length.
    #[must_use]
    pub fn zero_raw(length: usize) -> Self {
        Self::from_raw(vec![0; length])
    }
}

impl<C: DataMut<Elem = u64>> BfvCiphertext<C> {
    /// Borrows mutable `[c0,c1]` storage.
    #[must_use]
    pub fn as_mut_view(&mut self) -> BfvCiphertext<&mut [u64]> {
        let binding = self.binding.clone();
        BfvCiphertext {
            data: self.data.as_mut_slice(),
            binding,
        }
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
