use algebra::ring::Ring;

/// Plaintext type
pub struct Plaintext<R: Ring> {
    m: R,
}

impl<R: Ring> Plaintext<R> {
    /// Creates a new [`Plaintext<R>`].
    pub fn new(m: R) -> Self {
        Self { m }
    }
}
