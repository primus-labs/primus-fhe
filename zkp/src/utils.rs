//! This module defines some useful utils that may invoked by piop.
use algebra::{AbstractExtensionField, DenseMultilinearExtension, Field};

/// Generate MLE of the ideneity function eq(u,x) for x \in \{0, 1\}^dim
pub fn gen_identity_evaluations<F: Field, EF: AbstractExtensionField<F>>(
    u: &[EF],
) -> DenseMultilinearExtension<F, EF> {
    let dim = u.len();
    let mut evaluations: Vec<_> = vec![EF::zero(); 1 << dim];
    evaluations[0] = EF::one();
    for i in 0..dim {
        // The index represents a point in {0,1}^`num_vars` in little endian form.
        // For example, `0b1011` represents `P(1,1,0,1)`
        let u_i_rev = u[dim - i - 1];
        for b in (0..(1 << i)).rev() {
            evaluations[(b << 1) + 1] = evaluations[b] * u_i_rev;
            evaluations[b << 1] = evaluations[b] * (EF::one() - u_i_rev);
        }
    }
    DenseMultilinearExtension::from_evaluations_vec(dim, evaluations)
}

/// Evaluate eq(u, v) = \prod_i (u_i * v_i + (1 - u_i) * (1 - v_i))
pub fn eval_identity_function<F: Field, EF: AbstractExtensionField<F>>(u: &[EF], v: &[EF]) -> EF {
    assert_eq!(u.len(), v.len());
    let mut evaluation = EF::one();
    for (u_i, v_i) in u.iter().zip(v) {
        evaluation *= *u_i * *v_i + (EF::one() - *u_i) * (EF::one() - *v_i);
    }
    evaluation
}

#[cfg(test)]
mod test {
    use crate::utils::{eval_identity_function, gen_identity_evaluations};
    use algebra::{
        derive::{Field, Prime},
        BabyBearExetension, FieldUniformSampler, MultilinearExtension,
    };
    use rand::thread_rng;
    use rand_distr::Distribution;

    #[derive(Field, Prime)]
    #[modulus = 132120577]
    pub struct Fp32(u32);
    // field type
    type EF = BabyBearExetension;

    #[test]
    fn test_gen_identity_evaluations() {
        let sampler = <FieldUniformSampler<EF>>::new();
        let mut rng = thread_rng();
        let dim = 10;
        let u: Vec<_> = (0..dim).map(|_| sampler.sample(&mut rng)).collect();

        let identity_at_u = gen_identity_evaluations(&u);

        let v: Vec<_> = (0..dim).map(|_| sampler.sample(&mut rng)).collect();

        assert_eq!(eval_identity_function(&u, &v), identity_at_u.evaluate(&v));
    }
}
