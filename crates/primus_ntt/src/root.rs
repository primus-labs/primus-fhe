use primus_factor::{FactorBase, FactorMul, ShoupFactor};
use primus_integer::FheUint;
use primus_modulo::*;
use primus_reduce::FieldContext;
use rand::{distr::Uniform, prelude::*};

use crate::NttError;

pub trait PrimitiveRoot
where
    Self: FheUint,
{
    fn is_primitive_root<M>(self, log_degree: u32, modulus: M) -> bool
    where
        M: FieldContext<Self>;

    fn try_primitive_root<M>(log_degree: u32, modulus: M) -> Result<Self, NttError<Self>>
    where
        M: FieldContext<Self>;

    fn try_minimal_primitive_root<M>(log_degree: u32, modulus: M) -> Result<Self, NttError<Self>>
    where
        M: FieldContext<Self>;
}

impl<T: FheUint> PrimitiveRoot for T {
    fn is_primitive_root<M>(self, log_degree: u32, modulus: M) -> bool
    where
        M: FieldContext<Self>,
    {
        let modulus_value = unsafe { modulus.value_unchecked() };

        debug_assert!(self < modulus_value);
        debug_assert!(
            log_degree > 0,
            "degree must be a power of two and bigger than 1"
        );

        if self.is_zero() {
            return false;
        }

        self.exp_power_of_2_modulo(log_degree - 1, modulus) == modulus.minus_one()
    }

    fn try_primitive_root<M>(log_degree: u32, modulus: M) -> Result<Self, NttError<Self>>
    where
        M: FieldContext<Self>,
    {
        assert!(log_degree < T::BITS);

        let modulus_value = unsafe { modulus.value_unchecked() };

        // p-1
        let modulus_minus_one = modulus.minus_one();
        let degree = T::ONE << log_degree;

        // (p-1)/n
        let quotient = modulus_minus_one >> log_degree;

        // (p-1) must be divisible by n
        if modulus_minus_one != quotient * degree {
            return Err(NttError::NoPrimitiveRoot {
                degree,
                modulus: modulus_value,
            });
        }

        let mut rng = rand::rng();
        let distr = Uniform::new_inclusive(T::TWO, modulus_minus_one).unwrap();

        let mut w = T::ZERO;

        if (0..200).any(|_| {
            let r = distr.sample(&mut rng);

            w = r.exp_modulo(quotient, modulus);
            w.is_primitive_root(log_degree, modulus)
        }) {
            Ok(w)
        } else {
            Err(NttError::NoPrimitiveRoot {
                degree,
                modulus: modulus_value,
            })
        }
    }

    fn try_minimal_primitive_root<M>(log_degree: u32, modulus: M) -> Result<Self, NttError<Self>>
    where
        M: FieldContext<Self>,
    {
        let mut root = T::try_primitive_root(log_degree, modulus)?;

        let modulus_value = unsafe { modulus.value_unchecked() };

        let generator_sq = root.square_modulo(modulus);
        let generator_sq = ShoupFactor::new(generator_sq, modulus_value);
        let mut current_generator = root;

        let degree = 1u64 << log_degree;
        for _ in 0..degree {
            if current_generator < root {
                root = current_generator;
            }

            current_generator = generator_sq.factor_mul_modulo(current_generator, modulus_value);
        }

        Ok(root)
    }
}
