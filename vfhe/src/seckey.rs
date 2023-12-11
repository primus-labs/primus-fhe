use algebra::ring::Ring;

/// secret key
pub struct SecretKey<R: Ring> {
    data: Vec<R>,
}

impl<R: Ring> SecretKey<R> {
    /// Creates a new [`SecretKey<R>`].
    pub fn new(secret_key: Vec<R>) -> Self {
        Self { data: secret_key }
    }

    /// drop self, return the inner data.
    pub fn data(self) -> Vec<R> {
        self.data
    }
}
