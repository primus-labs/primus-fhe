//! Tests for the `#[derive(Barrett)]` proc macro — verifies that the generated
//! zero-sized modulus type compiles and produces correct results.

#![cfg(feature = "derive")]

use primus_modulus::Barrett;

#[derive(Barrett)]
#[modulus(ty = u32, value = 536813569)]
struct Modulus;

#[derive(Barrett)]
#[modulus(ty = u32, value = 132120577)]
struct _ModulusCheck;

#[cfg(all(test, feature = "derive"))]
mod u32tests {
    use primus_reduce::FieldContext;
    use primus_reduce::prelude::*;
    use rand::{distr::Uniform, prelude::*};

    use super::Modulus;

    type ValueT = u32;
    // type WideT = u64;

    fn field_trait<M: FieldContext<ValueT>>(_modulus: M) {}

    fn mul_mod(a: u32, b: u32) -> u32 {
        ((a as u64 * b as u64) % Modulus::value() as u64) as u32
    }

    #[test]
    fn scalar_ops() {
        field_trait(Modulus);
        let m = Modulus::value();
        let distr = Uniform::new(0, m).unwrap();
        let mut rng = rand::rng();
        let a = distr.sample(&mut rng);
        let b = distr.sample(&mut rng);
        let c = distr.sample(&mut rng);

        assert_eq!(Modulus.reduce_add(a, b), (a + b) % m);
        assert_eq!(Modulus.reduce_sub(a, b), (a + m - b) % m);
        assert_eq!(0, Modulus.reduce_add(a, Modulus.reduce_neg(a)));
        assert_eq!(Modulus.reduce_mul(a, b), mul_mod(a, b));
        assert_eq!(Modulus.reduce_square(a), mul_mod(a, a));
        assert_eq!(
            Modulus.reduce_mul_add(a, b, c),
            ((a as u64 * b as u64 + c as u64) % m as u64) as u32
        );
        if a != 0 {
            assert_eq!(1, Modulus.reduce_mul(a, Modulus.reduce_inv(a)));
        }
        if b != 0 {
            assert_eq!(a, Modulus.reduce_mul(b, Modulus.reduce_div(a, b)));
        }
    }

    #[test]
    fn slice_ops() {
        use primus_modulus::BarrettModulus;

        let m = Modulus::value();
        let distr = Uniform::new(0, m).unwrap();
        let mut rng = rand::rng();

        for &len in &[1usize, 3, 7, 8, 15, 16, 17, 31, 33, 64, 65] {
            let a: Vec<u32> = distr.sample_iter(&mut rng).take(len).collect();
            let b: Vec<u32> = distr.sample_iter(&mut rng).take(len).collect();
            let c: Vec<u32> = distr.sample_iter(&mut rng).take(len).collect();
            let scalar: u32 = distr.sample(&mut rng);

            // once
            let once_in: Vec<u32> = a
                .iter()
                .map(|&x| {
                    if rng.random_bool(0.5) {
                        x
                    } else {
                        x.wrapping_add(m)
                    }
                })
                .collect();
            let mut assign = once_in.clone();
            Modulus.reduce_once_slice_assign(&mut assign);
            assert_eq!(assign, a, "once_slice_assign len={len}");

            // add
            let mut add = a.clone();
            Modulus.reduce_add_slice_assign(&mut add, &b);
            let add_exp: Vec<u32> = a.iter().zip(&b).map(|(&x, &y)| (x + y) % m).collect();
            assert_eq!(add, add_exp, "add_slice_assign len={len}");

            // sub
            let mut sub = a.clone();
            Modulus.reduce_sub_slice_assign(&mut sub, &b);
            let sub_exp: Vec<u32> = a
                .iter()
                .zip(&b)
                .map(|(&x, &y)| if x >= y { x - y } else { x + m - y })
                .collect();
            assert_eq!(sub, sub_exp, "sub_slice_assign len={len}");

            // mul
            let expected_mul: Vec<u32> = a.iter().zip(&b).map(|(&x, &y)| mul_mod(x, y)).collect();
            let mut mul_a = a.clone();
            Modulus.reduce_mul_slice_assign(&mut mul_a, &b);
            assert_eq!(mul_a, expected_mul, "mul_slice_assign len={len}");

            // lazy_reduce_mul
            let mut lazy = a.clone();
            Modulus.lazy_reduce_mul_slice_assign(&mut lazy, &b);
            for v in lazy.iter_mut() {
                assert!(*v < m * 2);
                if *v >= m {
                    *v -= m;
                }
            }
            assert_eq!(lazy, expected_mul, "lazy_mul_slice_assign len={len}");

            // add_mul_slice_assign
            let mut acc = c.clone();
            Modulus.reduce_add_mul_slice_assign(&mut acc, &a, &b);
            let acc_exp: Vec<u32> = c
                .iter()
                .zip(&a)
                .zip(&b)
                .map(|((&z, &x), &y)| ((x as u64 * y as u64 + z as u64) % m as u64) as u32)
                .collect();
            assert_eq!(acc, acc_exp, "add_mul_slice_assign len={len}");

            // mul_add_slice_to
            let mut out = vec![0; len];
            Modulus.reduce_mul_add_slice_to(&a, &b, &c, &mut out);
            let abc_exp: Vec<u32> = a
                .iter()
                .zip(&b)
                .zip(&c)
                .map(|((&x, &y), &z)| ((x as u64 * y as u64 + z as u64) % m as u64) as u32)
                .collect();
            assert_eq!(out, abc_exp, "mul_add_slice_to len={len}");

            // scalar variants
            let expected_scalar: Vec<u32> = a.iter().map(|&x| mul_mod(x, scalar)).collect();
            let mut s_mul = a.clone();
            Modulus.reduce_mul_scalar_slice_assign(&mut s_mul, scalar);
            assert_eq!(s_mul, expected_scalar, "scalar_mul_slice_assign len={len}");

            let mut out = vec![0; len];
            Modulus.reduce_mul_scalar_add_slice_to(&b, scalar, &c, &mut out);
            let sbc_exp: Vec<u32> = b
                .iter()
                .zip(&c)
                .map(|(&y, &z)| ((scalar as u64 * y as u64 + z as u64) % m as u64) as u32)
                .collect();
            assert_eq!(out, sbc_exp, "scalar_mul_add_slice_to len={len}");

            // dot_product
            let expected = {
                let ref_m = BarrettModulus::<u32>::new(m);
                ref_m.reduce_dot_product(&a, &b)
            };
            assert_eq!(
                Modulus.reduce_dot_product(&a, &b),
                expected,
                "dot_product len={len}"
            );
            assert_eq!(
                Modulus.reduce_dot_product_iter(a.iter().copied(), b.iter().copied()),
                expected,
                "dot_product_iter len={len}"
            );
        }
    }
}
