//! Definition and implementation of polynomials.

mod polynomial_traits;

mod native_polynomial;
mod ntt_polynomial;

pub use polynomial_traits::*;

pub use native_polynomial::*;
pub use ntt_polynomial::*;

#[cfg(test)]
mod tests {
    use crate::field::{prime_fields::Fp32, NTTField};

    use super::*;

    #[test]
    fn test_transform() {
        const P: u32 = 1000000513;
        type Fp = Fp32<P>;
        type PolyFp = Polynomial<Fp>;

        let ntt_table = Fp::generate_ntt_table(3).unwrap();

        let a = PolyFp::new(vec![
            Fp::new(1),
            Fp::new(2),
            Fp::new(3),
            Fp::new(4),
            Fp::new(5),
            Fp::new(6),
            Fp::new(7),
            Fp::new(8),
        ]);
        let b = ntt_table.transform_inplace(a);

        println!("{:?}", b);

        let c = ntt_table.inverse_transform_inplace(b);

        println!("{:?}", c);
    }
}
