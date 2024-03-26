use algebra::Polynomial;

use crate::CipherField;

/// Define the public key of BFV.
#[derive(Clone, Debug, PartialEq)]
pub struct BFVPublicKey(pub [Polynomial<CipherField>; 2]);

impl BFVPublicKey {
    /// Creates a new instance.
    #[inline]
    pub fn new(polys: [Polynomial<CipherField>; 2]) -> Self {
        Self(polys)
    }
}
