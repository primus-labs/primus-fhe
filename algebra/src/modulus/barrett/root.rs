use rand::{distributions::Uniform, prelude::Distribution};

use crate::arith::PrimitiveRoot;
use crate::modulus::ShoupFactor;
use crate::numeric::Numeric;
use crate::reduce::{Modulus, ReduceExp, ReduceExpPowOf2, ReduceMulAssign, ReduceSquare};
use crate::AlgebraError;

use super::BarrettModulus;

impl<T: Numeric> PrimitiveRoot<T> for BarrettModulus<T> {
    #[inline]
    fn check_primitive_root(self, root: T, log_degree: u32) -> bool {
        debug_assert!(root < self.value);
        debug_assert!(
            log_degree > 0,
            "degree must be a power of two and bigger than 1"
        );

        if root.is_zero() {
            return false;
        }

        self.reduce_exp_power_of_2(root, log_degree - 1) == self.modulus_minus_one()
    }

    #[inline]
    fn try_primitive_root(self, log_degree: u32) -> Result<T, AlgebraError> {
        assert!(log_degree < T::BITS);

        // p-1
        let modulus_minus_one = self.modulus_minus_one();
        let degree = T::ONE << log_degree;

        // (p-1)/n
        let quotient = modulus_minus_one / degree;

        // (p-1) must be divisible by n
        if modulus_minus_one != quotient * degree {
            return Err(AlgebraError::NoPrimitiveRoot {
                degree: Box::new(degree),
                modulus: Box::new(self.value),
            });
        }

        let mut rng = rand::thread_rng();
        let distr = Uniform::new_inclusive(T::TWO, modulus_minus_one);

        let mut w = T::ZERO;

        if (0..100).any(|_| {
            let r = distr.sample(&mut rng);
            w = self.reduce_exp(r, quotient);
            self.check_primitive_root(w, log_degree)
        }) {
            Ok(w)
        } else {
            Err(AlgebraError::NoPrimitiveRoot {
                degree: Box::new(degree),
                modulus: Box::new(self.value),
            })
        }
    }

    #[inline]
    fn try_minimal_primitive_root(self, log_degree: u32) -> Result<T, AlgebraError> {
        let mut root = self.try_primitive_root(log_degree)?;

        let generator_sq = self.reduce_square(root);
        let generator_sq = ShoupFactor::new(generator_sq, self.value);
        let mut current_generator = root;

        let degree = 1u64 << log_degree;
        for _ in 0..degree {
            if current_generator < root {
                root = current_generator;
            }

            self.value
                .reduce_mul_assign(&mut current_generator, generator_sq);
        }

        Ok(root)
    }
}
