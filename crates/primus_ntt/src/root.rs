use primus_factor::{FactorMul, ShoupFactor};
use primus_integer::FheUint;
use primus_reduce::FieldContext;
use rand::{distr::Uniform, prelude::*};

use crate::NttError;

/// Tests power-of-two order in an odd prime field; the root must be canonical.
fn is_primitive_root<T: FheUint, M>(root: T, log_degree: u32, modulus: M) -> bool
where
    M: FieldContext<T>,
{
    let modulus_value = modulus.value();

    debug_assert!(root < modulus_value);
    debug_assert!(
        log_degree > 0,
        "degree must be a power of two and bigger than 1"
    );

    if root.is_zero() {
        return false;
    }

    modulus.reduce_exp_power_of_2(root, log_degree - 1) == modulus.minus_one()
}

/// Samples at most 200 candidates; the order must fit T and divide q - 1.
fn try_primitive_root<T: FheUint, M>(log_degree: u32, modulus: M) -> Result<T, NttError<T>>
where
    M: FieldContext<T>,
{
    assert!(log_degree < T::BITS);

    let modulus_value = modulus.value();

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

        w = modulus.reduce_exp(r, quotient);
        is_primitive_root(w, log_degree, modulus)
    }) {
        Ok(w)
    } else {
        Err(NttError::NoPrimitiveRoot {
            degree,
            modulus: modulus_value,
        })
    }
}

/// Finds the smallest primitive power-of-two root by enumerating odd powers.
/// Requires positive log_degree, an odd prime modulus and Shoup-compatible bounds.
pub(crate) fn try_minimal_primitive_root<T: FheUint, M>(
    log_degree: u32,
    modulus: M,
) -> Result<T, NttError<T>>
where
    M: FieldContext<T>,
{
    let mut root = try_primitive_root(log_degree, modulus)?;

    let modulus_value = modulus.value();

    let generator_sq = modulus.reduce_square(root);
    let generator_sq = ShoupFactor::new(generator_sq, modulus_value);
    let mut current_generator = root;

    let degree = 1u64 << log_degree;
    // For power-of-two order D, the D/2 odd powers are exactly the primitive
    // roots in the prime field. Multiplication by the sampled root's square
    // visits each once; another D/2 steps would repeat the same orbit.
    for _ in 0..degree / 2 {
        if current_generator < root {
            root = current_generator;
        }

        current_generator = generator_sq.factor_mul_modulo(current_generator, modulus_value);
    }

    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use primus_modulus::BarrettModulus;

    #[test]
    fn minimal_primitive_roots_match_integer_oracle() {
        fn check<T: FheUint>()
        where
            BarrettModulus<T>: FieldContext<T>,
        {
            let modulus = BarrettModulus::new(T::as_from(257u64));
            for log_degree in 1..=8 {
                // Search canonical integers directly: w^(D/2) = -1 proves order D
                // when D is a power of two. This oracle does not use Shoup arithmetic.
                let half_degree = 1u32 << (log_degree - 1);
                let expected = (2..257u64)
                    .find(|&candidate| {
                        (0..half_degree).fold(1, |power, _| power * candidate % 257) == 256
                    })
                    .unwrap();
                let actual = try_minimal_primitive_root(log_degree, modulus).unwrap();
                assert_eq!(actual, T::as_from(expected), "log_degree={log_degree}");
            }
            // Order 512 cannot divide 257-1; rejection happens before random search.
            assert!(matches!(try_minimal_primitive_root(9, modulus),
                Err(NttError::NoPrimitiveRoot { degree, modulus })
                    if degree == T::as_from(512u64) && modulus == T::as_from(257u64)
            ));
        }
        check::<u16>();
        check::<u32>();
        check::<u64>();
    }
}
