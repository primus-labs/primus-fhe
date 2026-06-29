#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use primus_decompose::primitive::ApproxSignedBasis;
    use primus_modulus::PowOf2Modulus;
    use primus_reduce::{ReduceMulAdd, ReduceSub};
    use rand::{RngExt, distr::Uniform};

    type ValueT = u32;
    type SignedT = i64;

    const LOG_MODULUS: u32 = 16;
    const MODULUS_MINUS_ONE: ValueT = ValueT::MAX >> (ValueT::BITS - LOG_MODULUS);

    #[test]
    fn test_pow_of_2_approx_signed_decompose() {
        let rng = rand::rng();

        let modulus = <PowOf2Modulus<ValueT>>::with_mask(MODULUS_MINUS_ONE);
        let basis = ApproxSignedBasis::new(Some(1 << LOG_MODULUS), 6, None);

        let differ_max = basis.approximate_error_bound();

        let basis_value = basis.basis_value();
        let log_basis = basis.log_basis() as usize;

        let distr = Uniform::new_inclusive(0, MODULUS_MINUS_ONE).unwrap();

        let mut decv = Vec::with_capacity(basis.decompose_length());
        for value in rng.sample_iter(distr).take(100) {
            decv.clear();

            let (value, mut carry) = basis.init_value_carry(value);
            for d in basis.decompose_iter() {
                let (di, ci) = d.decompose(value, carry);
                decv.push(di);
                carry = ci;
            }

            let result = basis
                .scalar_iter()
                .zip(decv.iter())
                .fold(0, |acc, (scalar, &dec)| {
                    modulus.reduce_mul_add(scalar, dec, acc)
                });

            let difference = modulus
                .reduce_sub(result, value)
                .min(modulus.reduce_sub(value, result));

            if difference > differ_max {
                let show = |value: ValueT| {
                    let value_str = format!("{:01$b}", value, LOG_MODULUS as usize);

                    let (pre, end) = value_str.split_at(log_basis * basis.decompose_length());

                    pre.chars().chunks(log_basis).into_iter().for_each(|v| {
                        let str: String = v.collect();
                        print!("{}|", str);
                    });
                    println!("{}", end);
                };

                println!("value");
                show(value);

                for &d in decv.iter().rev() {
                    if basis_value > 2 {
                        if d >= basis_value / 2 {
                            print!(
                                "{:1$}|",
                                d as SignedT - MODULUS_MINUS_ONE as SignedT - 1,
                                log_basis
                            );
                        } else {
                            print!("{:1$}|", d, log_basis);
                        }
                    } else {
                        print!("{:1$}|", d, log_basis);
                    }
                }
                println!();

                println!("value ={}", value);
                println!("result={}", result);
                println!("differ={}", difference);
                panic!("basis={}", basis_value)
            }
        }
    }
}
