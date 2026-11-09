use primus_data::{Data, DataMut, RawData};

/// Precomputed multiplication factors for one value under an ordered RNS basis.
///
/// Element `i` must be prepared from that value's residue using the basis's
/// `i`th modulus. Consumers require matching basis order and length. This storage
/// wrapper does not carry or validate the basis or factor precomputations.
/// It is distinct from [`crate::Residues`]: its elements contain precomputed
/// multiplication data and cannot be used directly for CRT reconstruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidueFactors<S: RawData>(pub S);

impl<S: RawData> ResidueFactors<S> {
    /// Wraps storage without allocation or validation of its basis or factors.
    #[must_use]
    #[inline]
    pub fn new(data: S) -> Self {
        Self(data)
    }

    /// Returns the underlying storage.
    #[must_use]
    #[inline]
    pub fn into_inner(self) -> S {
        self.0
    }
}

impl<S: Data> ResidueFactors<S> {
    /// Returns the number of factors, one per modulus.
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the storage is empty.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrows the factors without copying.
    #[must_use]
    #[inline]
    pub fn view(&self) -> ResidueFactors<&[S::Elem]> {
        ResidueFactors(self.as_ref())
    }

    /// Iterates over factors in basis order.
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, S::Elem> {
        self.as_ref().iter()
    }
}

impl<S: DataMut> ResidueFactors<S> {
    /// Mutably borrows the factors without copying.
    #[must_use]
    #[inline]
    pub fn view_mut(&mut self) -> ResidueFactors<&mut [S::Elem]> {
        ResidueFactors(self.as_mut())
    }
}

impl<S: Data> AsRef<[S::Elem]> for ResidueFactors<S> {
    #[inline]
    fn as_ref(&self) -> &[S::Elem] {
        self.0.as_slice()
    }
}

impl<S: DataMut> AsMut<[S::Elem]> for ResidueFactors<S> {
    #[inline]
    fn as_mut(&mut self) -> &mut [S::Elem] {
        self.0.as_mut_slice()
    }
}
