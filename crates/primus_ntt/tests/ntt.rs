#![cfg(target_arch = "x86_64")]

#[cfg(test)]
mod tests {
    use primus_modulus::BarrettModulus;
    use primus_ntt::{NttTable, U64NttTable, UintNttTable};
    use rand::{
        RngExt,
        distr::{Distribution, Uniform},
    };

    const N: usize = 2048;
    const LOG_N: u32 = N.trailing_zeros();

    #[test]
    fn test_bit_shift_32() {
        let q = 536813569u64;
        let modulus = <BarrettModulus<u64>>::new(q);
        let mut rng = rand::rng();
        let distr = Uniform::new(0, q).unwrap();

        let table = U64NttTable::new(LOG_N, modulus).unwrap();
        let uint_table = UintNttTable::new(LOG_N, modulus).unwrap();

        let mut poly: Vec<u64> = distr.sample_iter(&mut rng).take(N).collect();
        let mut poly_c = poly.clone();

        table.transform_slice(&mut poly);
        uint_table.transform_slice(&mut poly_c);
        assert_eq!(poly, poly_c);

        table.inverse_transform_slice(&mut poly);
        uint_table.inverse_transform_slice(&mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        table.transform_coeff_minus_one_monomial(degree, &mut poly);
        uint_table.transform_coeff_minus_one_monomial(degree, &mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        table.transform_coeff_one_monomial(degree, &mut poly);
        uint_table.transform_coeff_one_monomial(degree, &mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        let coeff = rng.sample(distr);
        table.transform_monomial(coeff, degree, &mut poly);
        uint_table.transform_monomial(coeff, degree, &mut poly_c);
        assert_eq!(poly, poly_c);
    }

    #[test]
    fn test_bit_shift_52() {
        let q = 562949953392641u64;
        let modulus = <BarrettModulus<u64>>::new(q);
        let mut rng = rand::rng();
        let distr = Uniform::new(0, q).unwrap();

        let table = U64NttTable::new(LOG_N, modulus).unwrap();
        let uint_table = UintNttTable::new(LOG_N, modulus).unwrap();

        let mut poly: Vec<u64> = distr.sample_iter(&mut rng).take(N).collect();
        let mut poly_c = poly.clone();

        table.transform_slice(&mut poly);
        uint_table.transform_slice(&mut poly_c);
        assert_eq!(poly, poly_c);

        table.inverse_transform_slice(&mut poly);
        uint_table.inverse_transform_slice(&mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        table.transform_coeff_minus_one_monomial(degree, &mut poly);
        uint_table.transform_coeff_minus_one_monomial(degree, &mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        table.transform_coeff_one_monomial(degree, &mut poly);
        uint_table.transform_coeff_one_monomial(degree, &mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        let coeff = rng.sample(distr);
        table.transform_monomial(coeff, degree, &mut poly);
        uint_table.transform_monomial(coeff, degree, &mut poly_c);
        assert_eq!(poly, poly_c);
    }

    #[test]
    fn test_bit_shift_64() {
        let q = 1152921504606830593u64;
        let modulus = <BarrettModulus<u64>>::new(q);
        let mut rng = rand::rng();
        let distr = Uniform::new(0, q).unwrap();

        let table = U64NttTable::new(LOG_N, modulus).unwrap();
        let uint_table = UintNttTable::new(LOG_N, modulus).unwrap();

        let mut poly: Vec<u64> = distr.sample_iter(&mut rng).take(N).collect();
        let mut poly_c = poly.clone();

        table.transform_slice(&mut poly);
        uint_table.transform_slice(&mut poly_c);
        assert_eq!(poly, poly_c);

        table.inverse_transform_slice(&mut poly);
        uint_table.inverse_transform_slice(&mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        table.transform_coeff_minus_one_monomial(degree, &mut poly);
        uint_table.transform_coeff_minus_one_monomial(degree, &mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        table.transform_coeff_one_monomial(degree, &mut poly);
        uint_table.transform_coeff_one_monomial(degree, &mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        let coeff = rng.sample(distr);
        table.transform_monomial(coeff, degree, &mut poly);
        uint_table.transform_monomial(coeff, degree, &mut poly_c);
        assert_eq!(poly, poly_c);
    }
}
