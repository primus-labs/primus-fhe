use algebra::ring::Ring;

/// secret key
#[derive(Debug, Clone)]
pub struct SecretKey<R: Ring> {
    data: Vec<R>,
}

impl<R: Ring> From<Vec<R>> for SecretKey<R> {
    #[inline]
    fn from(value: Vec<R>) -> Self {
        Self { data: value }
    }
}

impl<R: Ring> SecretKey<R> {
    /// Creates a new [`SecretKey<R>`].
    #[inline]
    pub fn new(secret_key: Vec<R>) -> Self {
        Self { data: secret_key }
    }

    /// Returns a reference to the data of this [`SecretKey<R>`].
    #[inline]
    pub fn data(&self) -> &[R] {
        self.data.as_ref()
    }
}
