#![cfg(target_arch = "x86_64")]

#[cfg(test)]
mod tests {
    use primus_modulus::BarrettModulus;
    use primus_ntt::{HexlNttTable, NttTable, UintNttTable};
    use rand::{
        RngExt,
        distr::{Distribution, Uniform},
    };

    // const N: usize = 512;
    // const N: usize = 1024;
    const N: usize = 2048;
    // const N: usize = 4096;
    const LOG_N: u32 = N.trailing_zeros();

    #[test]
    fn test_bit_shift_32() {
        let q = 536813569u64;
        let modulus = <BarrettModulus<u64>>::new(q);
        let mut rng = rand::rng();
        let distr = Uniform::new(0, q).unwrap();

        let hexl_table = HexlNttTable::new(LOG_N, modulus).unwrap();
        let uint_table = UintNttTable::new(LOG_N, modulus).unwrap();

        let mut poly: Vec<u64> = distr.sample_iter(&mut rng).take(N).collect();
        let mut poly_c = poly.clone();

        hexl_table.compute_forward(&mut poly, 1, 1);
        uint_table.transform_slice(&mut poly_c);
        assert_eq!(poly, poly_c);

        hexl_table.compute_inverse(&mut poly, 1, 1);
        uint_table.inverse_transform_slice(&mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        hexl_table.transform_coeff_minus_one_monomial(degree, &mut poly);
        uint_table.transform_coeff_minus_one_monomial(degree, &mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        hexl_table.transform_coeff_one_monomial(degree, &mut poly);
        uint_table.transform_coeff_one_monomial(degree, &mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        let coeff = rng.sample(distr);
        hexl_table.transform_monomial(coeff, degree, &mut poly);
        uint_table.transform_monomial(coeff, degree, &mut poly_c);
        assert_eq!(poly, poly_c);
    }

    #[test]
    fn test_bit_shift_52() {
        let q = 562949953392641u64;
        let modulus = <BarrettModulus<u64>>::new(q);
        let mut rng = rand::rng();
        let distr = Uniform::new(0, q).unwrap();

        let hexl_table = HexlNttTable::new(LOG_N, modulus).unwrap();
        let uint_table = UintNttTable::new(LOG_N, modulus).unwrap();

        let mut poly: Vec<u64> = distr.sample_iter(&mut rng).take(N).collect();
        let mut poly_c = poly.clone();

        hexl_table.compute_forward(&mut poly, 1, 1);
        uint_table.transform_slice(&mut poly_c);
        assert_eq!(poly, poly_c);

        hexl_table.compute_inverse(&mut poly, 1, 1);
        uint_table.inverse_transform_slice(&mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        hexl_table.transform_coeff_minus_one_monomial(degree, &mut poly);
        uint_table.transform_coeff_minus_one_monomial(degree, &mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        hexl_table.transform_coeff_one_monomial(degree, &mut poly);
        uint_table.transform_coeff_one_monomial(degree, &mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        let coeff = rng.sample(distr);
        hexl_table.transform_monomial(coeff, degree, &mut poly);
        uint_table.transform_monomial(coeff, degree, &mut poly_c);
        assert_eq!(poly, poly_c);
    }

    #[test]
    fn test_bit_shift_64() {
        let q = 1152921504606830593u64;
        let modulus = <BarrettModulus<u64>>::new(q);
        let mut rng = rand::rng();
        let distr = Uniform::new(0, q).unwrap();

        let hexl_table = HexlNttTable::new(LOG_N, modulus).unwrap();
        let uint_table = UintNttTable::new(LOG_N, modulus).unwrap();

        let mut poly: Vec<u64> = distr.sample_iter(&mut rng).take(N).collect();
        let mut poly_c = poly.clone();

        hexl_table.compute_forward(&mut poly, 1, 1);
        uint_table.transform_slice(&mut poly_c);
        assert_eq!(poly, poly_c);

        hexl_table.compute_inverse(&mut poly, 1, 1);
        uint_table.inverse_transform_slice(&mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        hexl_table.transform_coeff_minus_one_monomial(degree, &mut poly);
        uint_table.transform_coeff_minus_one_monomial(degree, &mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        hexl_table.transform_coeff_one_monomial(degree, &mut poly);
        uint_table.transform_coeff_one_monomial(degree, &mut poly_c);
        assert_eq!(poly, poly_c);

        let degree = rng.random_range(0..N);
        let coeff = rng.sample(distr);
        hexl_table.transform_monomial(coeff, degree, &mut poly);
        uint_table.transform_monomial(coeff, degree, &mut poly_c);
        assert_eq!(poly, poly_c);
    }
}
