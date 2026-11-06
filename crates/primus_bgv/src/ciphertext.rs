use crate::{BgvContext, binding::Binding};
use primus_data::{Data, DataMut};
use primus_poly::DcrtPolynomial;

/// Rejected provenance, geometry or canonical residues at a ciphertext import boundary.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BgvCiphertextBindingError {
    /// An already bound ciphertext belongs to a different context owner.
    #[error("BGV ciphertext belongs to another context")]
    ContextMismatch,
    /// The requested level was not prepared by this context.
    #[error("BGV ciphertext level {requested} is outside {available} prepared levels")]
    Level {
        /// Requested level.
        requested: usize,
        /// Number of prepared levels.
        available: usize,
    },
    /// An already bound ciphertext names a different level.
    #[error("BGV ciphertext level mismatch: expected {expected}, got {actual}")]
    BoundLevel {
        /// Required level.
        expected: usize,
        /// Recorded level.
        actual: usize,
    },
    /// Complete native ciphertext storage has the wrong length.
    #[error("BGV ciphertext length mismatch: expected {expected}, got {actual}")]
    Length {
        /// Required word count.
        expected: usize,
        /// Supplied word count.
        actual: usize,
    },
    /// A public ciphertext word is outside its corresponding modulus.
    #[error("BGV ciphertext word {index} is not canonical: {value} >= {modulus}")]
    NonCanonical {
        /// Word index in physical component-major storage.
        index: usize,
        /// Rejected residue.
        value: u64,
        /// Corresponding modulus.
        modulus: u64,
    },
}

/// A rank-one BGV ciphertext in physical component order `[c0, c1]`.
///
/// Each component is one modulus-major DCRT polynomial. Its phase is
/// `c0 + c1*s`; this is distinct from raw GLWE's mask/body representation.
/// Context-created containers retain their exact local owner and level.
/// Explicit raw containers instead inherit the consuming operation's caller
/// contracts; neither local provenance nor geometry proves the actual secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BgvCiphertext<C> {
    data: C,
    binding: Option<Binding>,
}

impl<C: Data<Elem = u64>> BgvCiphertext<C> {
    /// Wraps raw storage for explicit advanced interoperability.
    ///
    /// This does not establish provenance. The caller supplies the consuming
    /// operation's exact context, level, NTT convention and actual secret.
    /// Normal context-created ciphertexts carry and check context/level instead.
    #[must_use]
    pub fn from_raw(data: C) -> Self {
        Self {
            data,
            binding: None,
        }
    }

    pub(crate) fn from_bound(data: C, context: &BgvContext, level: usize) -> Self {
        Self {
            data,
            binding: Some(Binding::new(context, level)),
        }
    }

    pub(crate) fn check_binding(&self, context: &BgvContext, level: usize) {
        if let Some(binding) = &self.binding {
            binding.check(context, level);
        }
    }

    pub(crate) fn validate_binding(
        &self,
        context: &BgvContext,
        level: usize,
    ) -> Result<(), BgvCiphertextBindingError> {
        if let Some(binding) = &self.binding {
            binding.validate(context, level)?;
        }
        Ok(())
    }

    pub(crate) fn is_bound_to(&self, context: &BgvContext, level: usize) -> bool {
        self.binding
            .as_ref()
            .is_some_and(|binding| binding.validate(context, level).is_ok())
    }

    pub(crate) fn bind_context(&mut self, context: &BgvContext, level: usize) {
        self.check_binding(context, level);
        if self.binding.is_none() {
            self.binding = Some(Binding::new(context, level));
        }
    }

    pub(crate) fn bound_level(&self, context: &BgvContext) -> usize {
        self.binding
            .as_ref()
            .expect("raw BGV ciphertext recovery requires decrypt_at_level")
            .level(context)
    }

    /// Borrows the physical `[c0,c1]` storage.
    #[must_use]
    pub fn as_view(&self) -> BgvCiphertext<&[u64]> {
        BgvCiphertext {
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
                .expect("BGV ciphertext length overflow"),
            "BGV ciphertext length mismatch"
        );
        let (c0, c1) = self.as_ref().split_at(rns_poly_len);
        (DcrtPolynomial(c0), DcrtPolynomial(c1))
    }
}

impl BgvCiphertext<Vec<u64>> {
    /// Allocates raw zeroed storage without context or level provenance.
    #[must_use]
    pub fn zero_raw(length: usize) -> Self {
        Self::from_raw(vec![0; length])
    }
}

impl<C: DataMut<Elem = u64>> BgvCiphertext<C> {
    /// Borrows mutable `[c0,c1]` storage.
    #[must_use]
    pub fn as_mut_view(&mut self) -> BgvCiphertext<&mut [u64]> {
        let binding = self.binding.clone();
        BgvCiphertext {
            data: self.as_mut(),
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
                .expect("BGV ciphertext length overflow"),
            "BGV ciphertext length mismatch"
        );
        let (c0, c1) = self.as_mut().split_at_mut(rns_poly_len);
        (DcrtPolynomial(c0), DcrtPolynomial(c1))
    }
}

impl<C: Data<Elem = u64>> AsRef<[u64]> for BgvCiphertext<C> {
    fn as_ref(&self) -> &[u64] {
        self.data.as_slice()
    }
}

impl<C: DataMut<Elem = u64>> AsMut<[u64]> for BgvCiphertext<C> {
    fn as_mut(&mut self) -> &mut [u64] {
        self.data.as_mut_slice()
    }
}
