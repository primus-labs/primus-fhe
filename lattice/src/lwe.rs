use algebra::ring::Ring;

/// Represents a cryptographic structure based on the Learning with Errors (LWE) problem.
/// The LWE problem is a fundamental component in modern cryptography, often used to build
/// secure cryptographic systems that are considered hard to crack by quantum computers.
///
/// This structure contains two main components:
/// - `a`: A vector of elements of `R`, representing the public vector part of the LWE instance.
/// - `b`: An element of `R`, representing the response value which is computed as
///        the dot product of `a` with a secret vector, plus some noise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LWE<R: Ring> {
    a: Vec<R>,
    b: R,
}

impl<R: Ring> From<(Vec<R>, R)> for LWE<R> {
    /// Converts a tuple `(a, b)` into an instance of `Self`.
    ///
    /// # Arguments
    ///
    /// * `a` - A vector of type `R`.
    /// * `b` - An instance of type `R`.
    ///
    /// # Returns
    ///
    /// An instance of `Self`.
    #[inline]
    fn from((a, b): (Vec<R>, R)) -> Self {
        Self { a, b }
    }
}

impl<R: Ring> LWE<R> {
    /// Creates a new [`LWE<R>`].
    #[inline]
    pub fn new(a: Vec<R>, b: R) -> Self {
        Self { a, b }
    }

    /// Creates a new [`LWE<R>`] with reference.
    #[inline]
    pub fn from_ref(a: &[R], b: R) -> Self {
        Self { a: a.to_vec(), b }
    }

    /// Returns a reference to the `a` of this [`LWE<R>`].
    #[inline]
    pub fn a(&self) -> &[R] {
        self.a.as_ref()
    }

    /// Returns a mutable reference to the `a` of this [`LWE<R>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut Vec<R> {
        &mut self.a
    }

    /// Returns the `b` of this [`LWE<R>`].
    #[inline]
    pub fn b(&self) -> R {
        self.b
    }

    /// Returns a mutable reference to the `b` of this [`LWE<R>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut R {
        &mut self.b
    }

    /// Perform component-wise addition of two [`LWE<R>`].
    #[inline]
    pub fn add_component_wise(mut self, rhs: &Self) -> Self {
        self.add_inplace_component_wise(rhs);
        self
    }

    /// Perform component-wise subtraction of two [`LWE<R>`].
    #[inline]
    pub fn sub_component_wise(mut self, rhs: &Self) -> Self {
        self.sub_inplace_component_wise(rhs);
        self
    }

    /// Performs an in-place component-wise addition
    /// on the `self` [`LWE<R>`] with another `rhs` [`LWE<R>`].
    #[inline]
    pub fn add_inplace_component_wise(&mut self, rhs: &Self) {
        assert_eq!(self.a().len(), rhs.a().len());
        self.a_mut()
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v0, v1)| *v0 += *v1);
        *self.b_mut() += rhs.b();
    }

    /// Performs an in-place component-wise subtraction
    /// on the `self` [`LWE<R>`] with another `rhs` [`LWE<R>`].
    #[inline]
    pub fn sub_inplace_component_wise(&mut self, rhs: &Self) {
        assert_eq!(self.a().len(), rhs.a().len());
        self.a_mut()
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v0, v1)| *v0 -= *v1);
        *self.b_mut() -= rhs.b();
    }
}

#[cfg(test)]
mod tests {
    use algebra::field::{BarrettConfig, FieldDistribution, Fp32};
    use rand::distributions::Standard;
    use rand::prelude::*;

    use super::*;

    #[test]
    fn test_lwe() {
        const N: usize = 4;
        let rng = &mut rand::thread_rng();

        let a1 = rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>();
        let a2 = rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>();
        let a3 = a1
            .iter()
            .zip(a2.iter())
            .map(|(u, v)| *u + v)
            .collect::<Vec<Fp32>>();

        let b1: Fp32 = rng.gen();
        let b2: Fp32 = rng.gen();
        let b3: Fp32 = b1 + b2;

        let lwe1 = LWE::new(a1, b1);
        let lwe2 = LWE::new(a2, b2);
        let lwe3 = LWE::new(a3, b3);
        assert_eq!(lwe1.clone().add_component_wise(&lwe2), lwe3);
        assert_eq!(lwe3.clone().sub_component_wise(&lwe2), lwe1);
    }

    #[test]
    fn test_lwe_he() {
        const P: u32 = Fp32::BARRETT_MODULUS.value();
        const N: usize = 8;
        const T: u32 = 4;
        let rng = &mut rand::thread_rng();

        let chi = Fp32::normal_distribution(0., 3.2).unwrap();

        #[inline]
        fn encode(m: u32) -> Fp32 {
            Fp32::new((m as f64 * P as f64 / T as f64).round() as u32)
        }

        #[inline]
        fn decode(c: Fp32) -> u32 {
            (c.inner() as f64 * T as f64 / P as f64).round() as u32 % T
        }

        #[inline]
        fn dot_product<R: Ring>(u: &[R], v: &[R]) -> R {
            u.iter()
                .zip(v.iter())
                .fold(R::zero(), |acc, (x, y)| acc + *x * y)
        }

        let v0: u32 = rng.gen_range(0..T);
        let v1: u32 = rng.gen_range(0..T);

        let s = rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>();

        let lwe1 = {
            let a = rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>();
            let b: Fp32 = dot_product(&a, &s) + encode(v0) + chi.sample(rng);

            LWE::new(a, b)
        };

        let lwe2 = {
            let a = rng.sample_iter(Standard).take(N).collect::<Vec<Fp32>>();
            let b: Fp32 = dot_product(&a, &s) + encode(v1) + chi.sample(rng);

            LWE::new(a, b)
        };

        let ret = lwe1.add_component_wise(&lwe2);
        let decrypted = decode(ret.b() - dot_product(ret.a(), &s));
        assert_eq!(decrypted, (v0 + v1) % T);
    }
}
