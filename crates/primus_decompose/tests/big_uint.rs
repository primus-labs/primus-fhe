#[cfg(test)]
mod tests {
    use itertools::{Itertools, izip};
    use primus_decompose::big_integer::BigUintApproxSignedBasis;
    use primus_integer::{BigUint, BigUintIter, BigUintIterMut, multiply_many_values};
    use primus_modulus::BarrettModulus;
    use primus_reduce::prelude::*;
    use primus_rns::RNSBase;
    use rand::RngExt;
    use rand::distr::{Distribution, Uniform};
    use rayon::prelude::*;

    type ValueT = u32;
    type WideT = u64;
    type SignedT = i64;

    #[test]
    fn test_big_uint_value_single_decompose() {
        let mut rng = rand::rng();

        let moduli_value: [ValueT; 2] = [134215681, 134176769];
        let moduli = moduli_value.map(BarrettModulus::new);

        let distrs = moduli_value.map(|m| Uniform::new(0, m).unwrap());

        let rns_base = RNSBase::new(&moduli).unwrap();
        let composed_modulus = rns_base.moduli_product();
        let unused_bits = composed_modulus.0.last().unwrap().leading_zeros();
        let basis = BigUintApproxSignedBasis::new(composed_modulus, 7, None, &rns_base);

        println!("decompose_length: {}", basis.decompose_length());

        // make test simple
        assert!(basis.drop_bits() < ValueT::BITS);

        let difference_bound = basis
            .init_carry_mask()
            .map(|(a, b)| {
                assert_eq!(a, 0);
                b
            })
            .unwrap_or(0);

        println!("difference bound: {}", difference_bound);

        let basis_value = basis.basis_value();
        let log_basis = basis.log_basis() as usize;
        let mut decomposed_unsigned_value = Vec::with_capacity(basis.decompose_length());
        let mut difference = BigUint(vec![0; composed_modulus.len()]);

        let mut value = multiply_many_values(&distrs.map(|distr| rng.sample(distr)));
        value.0.resize(composed_modulus.len(), 0);

        let show = |value: &[ValueT]| {
            let mut value_str = String::new();
            let mut last = true;
            for &chunk in value.iter().rev() {
                if last {
                    value_str += &format!("{:01$b}", chunk, (ValueT::BITS - unused_bits) as usize);
                    last = false;
                } else {
                    value_str += &format!("{:01$b}", chunk, ValueT::BITS as usize);
                }
            }

            let (pre, end) = value_str.split_at(log_basis * basis.decompose_length());

            pre.chars().chunks(log_basis).into_iter().for_each(|v| {
                let str: String = v.collect();
                print!("{}|", str);
            });
            println!("{}", end);
        };

        println!("modulus: {:?}", composed_modulus);
        show(composed_modulus.0);

        println!("value");
        show(value.digits());

        let (adjust_value, mut carry) = basis.init_value_carry(&value);

        println!("adjust_value");
        show(&adjust_value);

        for decomposer in basis.decomposer_iter() {
            let (di, ci) = decomposer.unsigned_decompose(&adjust_value, carry);
            decomposed_unsigned_value.push(di);
            carry = ci;
        }

        let result = basis
            .iter_scalar_residues()
            .zip(decomposed_unsigned_value.iter())
            .fold(vec![0, 0], |mut acc, (scalar_residue, &unsigned_value)| {
                let value_chunk_residues = rns_base.wrapping_decompose(unsigned_value, basis_value);
                for (ac, value_chunk, &scalar, modulus) in
                    izip!(acc.iter_mut(), value_chunk_residues, scalar_residue, moduli)
                {
                    *ac = modulus.reduce_mul_add(scalar, value_chunk, *ac);
                }
                acc
            });
        let result = rns_base.compose(&result);

        for &unsigned_value in decomposed_unsigned_value.iter().rev() {
            if basis_value > 2 {
                if unsigned_value >= basis_value / 2 {
                    print!(
                        "{:1$}|",
                        -((basis_value - unsigned_value) as SignedT),
                        log_basis
                    );
                } else {
                    print!("{:1$}|", unsigned_value, log_basis);
                }
            } else {
                print!("{:1$}|", unsigned_value, log_basis);
            }
        }
        println!();

        let value = value;

        println!("value ={:?}", value);
        println!("result={:?}", result);

        if result.cmp(&value).is_le() {
            let _ = value.sub_to(&result, &mut difference);
        } else {
            let _ = result.sub_to(&value, &mut difference);
        }

        assert!(
            difference.cmp(&BigUint([difference_bound, 0])).is_le(),
            "value: {:?}\ndifference: {:?}",
            value,
            difference
        );

        println!("difference: {}", difference[0]);
    }

    #[test]
    fn batch_test_big_uint_value_single_decompose() {
        let mut rng = rand::rng();

        let moduli_value: [ValueT; 2] = [134215681, 134176769];
        let moduli = moduli_value.map(BarrettModulus::new);

        let distrs = moduli_value.map(|m| Uniform::new(0, m).unwrap());

        let rns_base = RNSBase::new(&moduli).unwrap();
        let composed_modulus = rns_base.moduli_product();
        let basis = BigUintApproxSignedBasis::new(composed_modulus, 7, None, &rns_base);

        // make test simple
        assert!(basis.drop_bits() < ValueT::BITS);

        let difference_bound = basis
            .init_carry_mask()
            .map(|(a, b)| {
                assert_eq!(a, 0);
                b
            })
            .unwrap_or(0);

        let basis_value = basis.basis_value();
        let mut decomposed_unsigned_value = vec![0; basis.decompose_length()];
        let mut difference = BigUint(vec![0; composed_modulus.len()]);

        for _ in 0..1_0000 {
            let mut value = multiply_many_values(&distrs.map(|distr| rng.sample(distr)));
            value.0.resize(composed_modulus.len(), 0);

            let (adjust_value, mut carry) = basis.init_value_carry(&value);

            for (decomposer, unsigned_value) in basis
                .decomposer_iter()
                .zip(decomposed_unsigned_value.iter_mut())
            {
                (*unsigned_value, carry) = decomposer.unsigned_decompose(&adjust_value, carry);
            }

            let result = basis
                .iter_scalar_residues()
                .zip(decomposed_unsigned_value.iter())
                .fold(vec![0, 0], |mut acc, (scalar_residue, &unsigned_value)| {
                    let value_chunk_residues =
                        rns_base.wrapping_decompose(unsigned_value, basis_value);
                    for (ac, value_chunk, &scalar, modulus) in
                        izip!(acc.iter_mut(), value_chunk_residues, scalar_residue, moduli)
                    {
                        *ac = modulus.reduce_mul_add(scalar, value_chunk, *ac);
                    }
                    acc
                });
            let result = rns_base.compose(&result);
            let value = value;

            if result.cmp(&value).is_le() {
                let _ = value.sub_to(&result, &mut difference);
            } else {
                let _ = result.sub_to(&value, &mut difference);
            }

            assert!(
                difference.cmp(&BigUint([difference_bound, 0])).is_le(),
                "value: {:?}\ndifference: {:?}",
                value,
                difference
            );
        }
    }

    #[test]
    fn test_big_uint_value_slice_decompose() {
        const N: usize = 32;

        let mut rng = rand::rng();

        let moduli_value: [ValueT; 2] = [134215681, 134176769];
        let moduli_count = moduli_value.len();
        let moduli = moduli_value.map(BarrettModulus::new);
        let distrs = moduli_value.map(|m| Uniform::new(0, m).unwrap());

        let rns_base = RNSBase::new(&moduli).unwrap();
        let modulus = rns_base.moduli_product();
        let big_uint_value_len = modulus.len();
        let basis = BigUintApproxSignedBasis::new(modulus, 5, None, &rns_base);
        let basis_value = basis.basis_value();

        let difference_bound = basis
            .init_carry_mask()
            .map(|(a, b)| {
                assert_eq!(a, 0);
                b
            })
            .unwrap_or(0);

        println!("difference bound: {}", difference_bound);

        let mut input_residues: Vec<ValueT> = vec![0; N * moduli_count];
        input_residues
            .as_chunks_mut::<N>()
            .0
            .iter_mut()
            .zip(distrs)
            .for_each(|(r, d)| {
                r.iter_mut()
                    .zip((&mut rng).sample_iter(d))
                    .for_each(|(a, b)| {
                        *a = b;
                    });
            });

        let mut input_values: Vec<ValueT> = vec![0; N * big_uint_value_len];
        let mut compose_buffer = vec![0; moduli_count];
        rns_base.compose_multiple_values_to(
            &input_residues,
            &mut input_values,
            N,
            &mut compose_buffer,
        );

        let mut adjust_big_uint_values = vec![0; N * big_uint_value_len];
        let mut carries = vec![false; N];
        basis.init_value_carry_slice(
            &input_values,
            &mut adjust_big_uint_values,
            &mut carries,
            big_uint_value_len,
        );

        let mut residues: Vec<ValueT> = vec![0; N * moduli_count];
        let mut decomposed_unsigned_values = vec![0; N];
        let mut temp: Vec<ValueT> = vec![0; N * moduli_count];

        basis
            .decomposer_iter()
            .zip(basis.iter_scalar_residues())
            .for_each(|(once_decomposer, scalar)| {
                once_decomposer.unsigned_decompose_slice_to(
                    &adjust_big_uint_values,
                    &mut decomposed_unsigned_values,
                    &mut carries,
                    big_uint_value_len,
                );

                assert!(decomposed_unsigned_values.iter().all(|&v| v < basis_value));

                rns_base.wrapping_decompose_small_values_to(
                    &decomposed_unsigned_values,
                    &mut temp,
                    N,
                    basis_value,
                );

                izip!(
                    residues.as_chunks_mut::<N>().0.iter_mut(),
                    temp.as_chunks::<N>().0.iter(),
                    scalar,
                    &moduli
                )
                .for_each(|(a, b, &scalar, m)| {
                    a.iter_mut()
                        .zip(b)
                        .for_each(|(x, &y)| *x = m.reduce_mul_add(y, scalar, *x));
                });
            });

        let mut output_values: Vec<ValueT> = vec![0; N * big_uint_value_len];
        rns_base.compose_multiple_values_to(&residues, &mut output_values, N, &mut compose_buffer);

        let mut min: Vec<ValueT> = vec![0; N * big_uint_value_len];

        izip!(
            BigUintIter::new(&input_values, big_uint_value_len),
            BigUintIter::new(&output_values, big_uint_value_len),
            BigUintIterMut::new(&mut min, big_uint_value_len),
        )
        .for_each(|(i, o, mut m)| {
            if i.cmp(&o).is_le() {
                let _ = o.sub_to(&i, &mut m);
            } else {
                let _ = i.sub_to(&o, &mut m);
            }
        });

        for &differ in min.iter().step_by(big_uint_value_len) {
            if differ > difference_bound {
                println!("differ={}", differ);
            }
        }

        assert!(
            min.iter()
                .step_by(big_uint_value_len)
                .all(|&v| v <= difference_bound)
        )
    }

    #[test]
    fn compare_signed_and_unsigned_decompse() {
        let mut rng = rand::rng();

        let moduli_value: [ValueT; 2] = [134215681, 134176769];
        let moduli = moduli_value.map(BarrettModulus::new);
        let moduli_count = moduli.len();

        let rns_base = RNSBase::new(&moduli).unwrap();
        let big_uint_value_len = rns_base.big_uint_value_len();
        let composed_modulus = rns_base.moduli_product();
        let basis = BigUintApproxSignedBasis::new(composed_modulus, 5, None, &rns_base);

        assert_eq!(moduli_count, 2);
        assert_eq!(big_uint_value_len, 2);

        let basis_value = basis.basis_value();

        let modulus: WideT = 134215681 * 134176769;

        let random_values: Vec<WideT> = Uniform::new(0, modulus)
            .unwrap()
            .sample_iter(&mut rng)
            .take(1_0000)
            .collect();

        random_values.par_iter().for_each(|i| {
            let input_big_uint_value: [ValueT; 2] = [*i as ValueT, (i >> 32) as ValueT];
            let mut adjust_big_uint_values: [ValueT; 2] = [0, 0];

            let mut carries: [bool; 1] = [false; 1];
            let mut decomposed_big_uint_values: [ValueT; 2] = [0, 0];

            let mut decomposed_unsigned_values: [ValueT; 1] = [0];
            let mut residues1: [ValueT; 2] = [0, 0];
            let mut residues2: [ValueT; 2] = [0, 0];

            basis.init_value_carry_slice(
                &input_big_uint_value,
                &mut adjust_big_uint_values,
                &mut carries,
                big_uint_value_len,
            );

            basis.decomposer_iter().for_each(|once_decomposer| {
                let mut temp = carries;
                once_decomposer.unsigned_decompose_slice_to(
                    &adjust_big_uint_values,
                    &mut decomposed_unsigned_values,
                    &mut temp,
                    big_uint_value_len,
                );

                rns_base.wrapping_decompose_small_values_to(
                    &decomposed_unsigned_values,
                    &mut residues1,
                    1,
                    basis_value,
                );

                once_decomposer.decompose_slice_to(
                    &adjust_big_uint_values,
                    &mut decomposed_big_uint_values,
                    &mut carries,
                    big_uint_value_len,
                );

                rns_base.decompose_big_uint_values_to(
                    &decomposed_big_uint_values,
                    &mut residues2,
                    1,
                );

                assert_eq!(residues1, residues2, "{}", decomposed_unsigned_values[0]);
                assert_eq!(temp, carries);
            });
        });
    }

    #[test]
    fn test_split() {
        let rng = rand::rng();
        let moduli_value: [ValueT; 2] = [134215681, 134176769];
        let moduli = moduli_value.map(BarrettModulus::new);

        let rns_base = RNSBase::new(&moduli).unwrap();
        let big_uint_value_len = rns_base.big_uint_value_len();
        let composed_modulus = rns_base.moduli_product();
        let basis = BigUintApproxSignedBasis::new(composed_modulus, 5, None, &rns_base);

        let modulus: WideT = 134215681 * 134176769;

        if basis.split_value().is_some() {
            let random_values: Vec<WideT> = Uniform::new(0, modulus)
                .unwrap()
                .sample_iter(rng)
                .take(1_0000)
                .collect();

            random_values.par_iter().for_each(|i: &WideT| {
                let input_big_uint_value: [ValueT; 2] = [*i as ValueT, (i >> 32) as ValueT];

                let mut adjust_big_uint_values: [ValueT; 2] = [0, 0];
                let mut carries: [bool; 1] = [false; 1];
                let mut decomposed_unsigned_values: [ValueT; 1] = [0];

                basis.init_value_carry_slice(
                    &input_big_uint_value,
                    &mut adjust_big_uint_values,
                    &mut carries,
                    big_uint_value_len,
                );

                basis.decomposer_iter().for_each(|once_decomposer| {
                    once_decomposer.unsigned_decompose_slice_to(
                        &input_big_uint_value,
                        &mut decomposed_unsigned_values,
                        &mut carries,
                        big_uint_value_len,
                    );
                });

                if BigUint(input_big_uint_value).cmp(&composed_modulus).is_ge() {
                    assert!(carries[0]);
                }
            });
        } else {
            println!("No Split Value!")
        }
    }
}
