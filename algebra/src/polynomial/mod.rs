//! Definition and implementation of polynomials.

mod polynomial_traits;

mod native_polynomial;
mod ntt_polynomial;

pub use polynomial_traits::*;

pub use native_polynomial::*;
pub use ntt_polynomial::*;

#[cfg(test)]
mod tests {
    use rand::prelude::*;

    use crate::field::BarrettConfig;
    use crate::field::NTTField;

    use super::*;

    use algebra_derive::{AlgebraRandom, Field, NTTField, Prime, Ring};

    #[derive(
        Clone,
        Copy,
        Debug,
        Default,
        Eq,
        PartialEq,
        PartialOrd,
        Ord,
        Ring,
        Field,
        AlgebraRandom,
        Prime,
        NTTField,
    )]
    #[modulus = 132120577]
    pub struct Fp32(u32);

    #[test]
    fn test_transform() {
        type Fp = Fp32;
        type PolyFp = Polynomial<Fp>;

        let p = Fp32::BARRETT_MODULUS.value();
        let log_n = 3;

        Fp::init_ntt_table(&[log_n]).unwrap();

        let distr = rand::distributions::Uniform::new(0, p);
        let rng = thread_rng();

        let coeffs = rng
            .sample_iter(distr)
            .take(1 << log_n)
            .map(Fp32::new)
            .collect::<Vec<Fp32>>();

        let a = PolyFp::new(coeffs);
        let b = a.clone().to_ntt_polynomial();
        let c = b.clone().to_native_polynomial();
        let d = c.clone().to_ntt_polynomial();
        assert_eq!(a, c);
        assert_eq!(b, d);
    }
}
