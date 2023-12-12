use algebra::ring::Ring;

/// Plaintext type
#[derive(Debug, Clone, Copy)]
pub struct Plaintext<R: Ring> {
    data: R,
}

impl<R: Ring> std::ops::Deref for Plaintext<R> {
    type Target = R;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<R: Ring> Plaintext<R> {
    /// Creates a new [`Plaintext<R>`].
    #[inline]
    pub fn new(data: R) -> Self {
        Self { data }
    }

    /// Returns the data of this [`Plaintext<R>`].
    #[inline]
    pub fn data(&self) -> R {
        self.data
    }
}
