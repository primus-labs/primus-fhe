use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;

/// The residues of one value under an ordered RNS basis.
///
/// Element `i` represents the value modulo the basis's `i`th modulus. Consumers
/// require canonical residues and a matching basis order and length. This storage
/// wrapper does not carry the basis or validate those conditions; mutable storage
/// may be allocated first and initialized by a decomposition or conversion API.
/// It does not represent a batch of values or precomputed multiplication factors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Residues<S: RawData>(pub S)
where
    S::Elem: FheUint;

impl<S: RawData> Residues<S>
where
    S::Elem: FheUint,
{
    /// Wraps storage without allocation or validation of its basis or values.
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

impl<S: Data> Residues<S>
where
    S::Elem: FheUint,
{
    /// Returns the number of residues, one per modulus.
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

    /// Borrows the residues without copying.
    #[must_use]
    #[inline]
    pub fn view(&self) -> Residues<&[S::Elem]> {
        Residues(self.as_ref())
    }

    /// Iterates over residues in basis order.
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, S::Elem> {
        self.as_ref().iter()
    }
}

impl<S: DataMut> Residues<S>
where
    S::Elem: FheUint,
{
    /// Mutably borrows the residues without copying.
    #[must_use]
    #[inline]
    pub fn view_mut(&mut self) -> Residues<&mut [S::Elem]> {
        Residues(self.as_mut())
    }
}

impl<S: Data> AsRef<[S::Elem]> for Residues<S>
where
    S::Elem: FheUint,
{
    #[inline]
    fn as_ref(&self) -> &[S::Elem] {
        self.0.as_slice()
    }
}

impl<S: DataMut> AsMut<[S::Elem]> for Residues<S>
where
    S::Elem: FheUint,
{
    #[inline]
    fn as_mut(&mut self) -> &mut [S::Elem] {
        self.0.as_mut_slice()
    }
}
