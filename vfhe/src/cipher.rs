use algebra::ring::Ring;
use lattice::LWE;

/// cipher text
#[derive(Debug, Clone)]
pub struct Ciphertext<R: Ring> {
    data: LWE<R>,
}

impl<R: Ring> From<LWE<R>> for Ciphertext<R> {
    #[inline]
    fn from(value: LWE<R>) -> Self {
        Self { data: value }
    }
}

impl<R: Ring> std::ops::Deref for Ciphertext<R> {
    type Target = LWE<R>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<R: Ring> Ciphertext<R> {
    /// Creates a new [`Ciphertext<R>`].
    #[inline]
    pub fn new(data: LWE<R>) -> Self {
        Self { data }
    }

    /// Returns a reference to the data of this [`Ciphertext<R>`].
    #[inline]
    pub fn data(&self) -> &LWE<R> {
        &self.data
    }
}
