use algebra::ring::Ring;
use lattice::LWE;

/// cipher text
#[derive(Debug, Clone)]
pub struct Ciphertext<R: Ring> {
    data: LWE<R>,
}

impl<R: Ring> From<(Vec<R>, R)> for Ciphertext<R> {
    #[inline]
    fn from((a, b): (Vec<R>, R)) -> Self {
        Self {
            data: <LWE<R>>::new(a, b),
        }
    }
}

impl<R: Ring> From<LWE<R>> for Ciphertext<R> {
    #[inline]
    fn from(value: LWE<R>) -> Self {
        Self { data: value }
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

    /// Perform component-wise addition.
    #[inline]
    pub fn no_boot_add(self, rhs: &Ciphertext<R>) -> Self {
        Self {
            data: self.data.add_component_wise(rhs.data()),
        }
    }
}
