#[cfg(test)]
#[cfg(feature = "concrete-ntt")]
mod tests {
    use algebra::{
        AbstractExtensionField, BabyBear, BabyBearExetension, FieldUniformSampler, Goldilocks,
        GoldilocksExtension,
    };
    use num_traits::{Inv, One};
    use rand::thread_rng;
    use rand_distr::Distribution;

    #[test]
    fn baby_bear_extension_test() {
        let mut rng = thread_rng();

        let a = BabyBearExetension::random(&mut rng);

        let b = BabyBearExetension::random(&mut rng);

        let c: BabyBear = FieldUniformSampler::new().sample(&mut rng);
        let c_ext = BabyBearExetension::from_base(c);

        assert_eq!(a + b, b + a);
        assert_eq!(a - b, -(b - a));
        assert_eq!(a + c, c_ext + a);
        assert_eq!(a - c, -(c_ext - a));
        assert_eq!((a / b) * b, a);

        assert_eq!(a * b, b * a);
        assert_eq!(a * c, a * c_ext);

        let a_inv = a.inv();

        assert_eq!(a * a_inv, BabyBearExetension::one());
    }

    #[test]
    fn goldilocks_extension_test() {
        let mut rng = thread_rng();

        let a = GoldilocksExtension::random(&mut rng);

        let b = GoldilocksExtension::random(&mut rng);

        let c: Goldilocks = FieldUniformSampler::new().sample(&mut rng);
        let c_ext = GoldilocksExtension::from_base(c);

        assert_eq!(a + b, b + a);
        assert_eq!(a + c, c_ext + a);
        assert_eq!(a + c, c_ext + a);
        assert_eq!(a - c, -(c_ext - a));
        assert_eq!((a / b) * b, a);

        assert_eq!(a * b, b * a);
        assert_eq!(a * c, a * c_ext);

        let a_inv = a.inv();

        assert_eq!(a * a_inv, GoldilocksExtension::one());
    }
}
