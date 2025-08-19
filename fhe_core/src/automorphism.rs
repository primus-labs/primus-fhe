use std::sync::Arc;

use algebra::{
    arith::Xgcd, decompose::NonPowOf2ApproxSignedBasis, modulus::PowOf2Modulus,
    ntt::NumberTheoryTransform, polynomial::FieldPolynomial, random::DiscreteGaussian,
    reduce::ReduceMul, utils::Size, Field, NttField,
};
use lattice::{
    utils::{NttRlweSpace, PolyDecomposeSpace},
    NttGadgetRlwe,
};
use num_traits::One;
use rand::{CryptoRng, Rng};

use crate::{NttRlweCiphertext, NttRlweSecretKey, RlweCiphertext, RlweSecretKey};

/// This defines the operation when perform automorphism on each coefficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Add,
    Sub,
}

/// This defines the operation and the source index
/// when perform automorphism on each coefficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FromOp {
    from: usize,
    op: Op,
}

#[derive(Debug, Clone)]
pub enum AutoHelper {
    Permutation(Vec<FromOp>),
    DimensionPlusOne,
    One,
}

/// Automorphism key
pub struct AutoKey<F: NttField> {
    degree: usize,
    auto_helper: AutoHelper,
    key: NttGadgetRlwe<F>,
    pub(crate) ntt_table: Arc<<F as NttField>::Table>,
}

impl<F: NttField> Clone for AutoKey<F> {
    fn clone(&self) -> Self {
        Self {
            degree: self.degree,
            auto_helper: self.auto_helper.clone(),
            key: self.key.clone(),
            ntt_table: Arc::clone(&self.ntt_table),
        }
    }
}

/// Preallocated space for automorphism
pub struct AutoSpace<F: NttField> {
    decompose_space: PolyDecomposeSpace<F>,
    ntt_rlwe_space: NttRlweSpace<F>,
}

impl<F: NttField> AutoSpace<F> {
    /// Creates a new [`AutoSpace<F>`].
    #[inline]
    pub fn new(dimension: usize) -> Self {
        Self {
            decompose_space: PolyDecomposeSpace::new(dimension),
            ntt_rlwe_space: NttRlweSpace::new(dimension),
        }
    }
}

impl<F: NttField> AutoKey<F> {
    /// Creates a new [`AutoKey<F>`].
    #[inline]
    pub fn new<R>(
        secret_key: &RlweSecretKey<F>,
        ntt_secret_key: &NttRlweSecretKey<F>,
        degree: usize,
        basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: &DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: Arc<<F as NttField>::Table>,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let rlwe_dimension = secret_key.coeff_count();
        assert!(degree & 1 == 1 && Xgcd::gcd(degree, rlwe_dimension << 1) == 1);

        let auto_helper;
        let key = if degree.is_one() {
            auto_helper = AutoHelper::One;
            NttGadgetRlwe::generate_random_neg_secret_sample(
                ntt_secret_key,
                basis,
                gaussian,
                &ntt_table,
                rng,
            )
        } else {
            auto_helper = if degree == rlwe_dimension + 1 {
                AutoHelper::DimensionPlusOne
            } else {
                AutoHelper::Permutation(generate_permutate_ops(degree, rlwe_dimension))
            };

            let p_auto = poly_auto(secret_key, &auto_helper);
            let auto_sk = ntt_table.transform_inplace(-p_auto);
            NttGadgetRlwe::generate_random_poly_sample(
                ntt_secret_key,
                &auto_sk,
                basis,
                gaussian,
                &ntt_table,
                rng,
            )
        };

        Self {
            key,
            auto_helper,
            ntt_table,
            degree,
        }
    }

    /// Performs automorphism on the given RLWE ciphertext.
    #[inline]
    pub fn automorphism(&self, ciphertext: &RlweCiphertext<F>) -> RlweCiphertext<F> {
        if let AutoHelper::One = self.auto_helper {
            ciphertext.clone()
        } else {
            let a = poly_auto(ciphertext.a(), &self.auto_helper);

            let mut result = self
                .key
                .mul_polynomial(&a, &self.ntt_table)
                .to_rlwe(&self.ntt_table);

            poly_auto_add_inplace(ciphertext.b(), &self.auto_helper, result.b_mut());

            result
        }
    }

    /// Performs automorphism on the given RLWE ciphertext in place.
    pub fn automorphism_inplace(
        &self,
        ciphertext: &RlweCiphertext<F>,
        auto_space: &mut AutoSpace<F>,
        destination: &mut RlweCiphertext<F>,
    ) {
        poly_auto_inplace(ciphertext.a(), &self.auto_helper, destination.a_mut());

        self.key.mul_polynomial_inplace(
            destination.a(),
            &self.ntt_table,
            &mut auto_space.decompose_space,
            &mut auto_space.ntt_rlwe_space,
        );

        auto_space
            .ntt_rlwe_space
            .inverse_transform_inplace(&self.ntt_table, destination);

        poly_auto_add_inplace(ciphertext.b(), &self.auto_helper, destination.b_mut());
    }

    /// Performs automorphism on the given RLWE ciphertext in place.
    pub fn automorphism_ntt_inplace(
        &self,
        ciphertext: &RlweCiphertext<F>,
        auto_space: &mut AutoSpace<F>,
        poly_space: &mut FieldPolynomial<F>,
        destination: &mut NttRlweCiphertext<F>,
    ) {
        poly_auto_inplace(ciphertext.a(), &self.auto_helper, poly_space);

        self.key.mul_polynomial_inplace(
            poly_space,
            &self.ntt_table,
            &mut auto_space.decompose_space,
            &mut auto_space.ntt_rlwe_space,
        );

        poly_auto_inplace(ciphertext.b(), &self.auto_helper, poly_space);

        self.ntt_table.transform_slice(poly_space.as_mut_slice());

        destination.a_mut().copy_from(auto_space.ntt_rlwe_space.a());
        destination.b_mut().copy_from(poly_space);
        *destination.b_mut() += auto_space.ntt_rlwe_space.b();
    }
}

impl<F: NttField> Size for AutoKey<F> {
    #[inline]
    fn size(&self) -> usize {
        self.key.size()
    }
}

#[inline]
fn generate_permutate_ops(degree: usize, dimension: usize) -> Vec<FromOp> {
    let twice_dimension = dimension << 1;
    let modulus = <PowOf2Modulus<usize>>::new(twice_dimension);

    let mut result = vec![
        FromOp {
            from: 0,
            op: Op::Add
        };
        dimension
    ];

    for i in 0..dimension {
        let to = modulus.reduce_mul(i, degree);
        if to < dimension {
            result[to] = FromOp {
                from: i,
                op: Op::Add,
            };
        } else {
            result[to - dimension] = FromOp {
                from: i,
                op: Op::Sub,
            };
        }
    }
    result
}

#[inline]
fn poly_auto<F: NttField>(
    poly: &FieldPolynomial<F>,
    auto_helper: &AutoHelper,
) -> FieldPolynomial<F> {
    match auto_helper {
        AutoHelper::Permutation(from_ops) => poly_auto_for_permutation(poly, from_ops),
        AutoHelper::DimensionPlusOne => poly_auto_for_dimension_plus_one(poly),
        AutoHelper::One => poly_auto_for_one(poly),
    }
}

#[inline]
fn poly_auto_inplace<F: NttField>(
    poly: &FieldPolynomial<F>,
    auto_helper: &AutoHelper,
    destination: &mut FieldPolynomial<F>,
) {
    match auto_helper {
        AutoHelper::Permutation(from_ops) => {
            poly_auto_inplace_for_permutation(poly, from_ops, destination);
        }
        AutoHelper::DimensionPlusOne => {
            poly_auto_inplace_for_dimension_plus_one(poly, destination);
        }
        AutoHelper::One => poly_auto_inplace_for_one(poly, destination),
    }
}

#[inline]
fn poly_auto_add_inplace<F: NttField>(
    poly: &FieldPolynomial<F>,
    auto_helper: &AutoHelper,
    destination: &mut FieldPolynomial<F>,
) {
    match auto_helper {
        AutoHelper::Permutation(from_ops) => {
            poly_auto_add_inplace_for_permutation(poly, from_ops, destination)
        }
        AutoHelper::DimensionPlusOne => {
            poly_auto_add_inplace_for_dimension_plus_one(poly, destination);
        }
        AutoHelper::One => poly_auto_add_inplace_for_one(poly, destination),
    }
}

#[inline]
fn poly_auto_for_one<F: NttField>(poly: &FieldPolynomial<F>) -> FieldPolynomial<F> {
    poly.clone()
}

#[inline]
fn poly_auto_inplace_for_one<F: NttField>(
    poly: &FieldPolynomial<F>,
    destination: &mut FieldPolynomial<F>,
) {
    destination.copy_from(poly);
}

#[inline]
fn poly_auto_add_inplace_for_one<F: NttField>(
    poly: &FieldPolynomial<F>,
    destination: &mut FieldPolynomial<F>,
) {
    *destination += poly;
}

#[inline]
fn poly_auto_for_permutation<F: NttField>(
    poly: &FieldPolynomial<F>,
    from_ops: &[FromOp],
) -> FieldPolynomial<F> {
    FieldPolynomial::new(
        from_ops
            .iter()
            .map(|from_op| {
                let c = unsafe { poly.as_slice().get_unchecked(from_op.from) };
                match from_op.op {
                    Op::Add => *c,
                    Op::Sub => F::neg(*c),
                }
            })
            .collect(),
    )
}

#[inline]
fn poly_auto_inplace_for_permutation<F: NttField>(
    poly: &FieldPolynomial<F>,
    from_ops: &[FromOp],
    destination: &mut FieldPolynomial<F>,
) {
    for (d, from_op) in destination.iter_mut().zip(from_ops.iter()) {
        let c = unsafe { poly.as_slice().get_unchecked(from_op.from) };
        match from_op.op {
            Op::Add => {
                *d = *c;
            }
            Op::Sub => {
                *d = F::neg(*c);
            }
        }
    }
}

#[inline]
fn poly_auto_add_inplace_for_permutation<F: NttField>(
    poly: &FieldPolynomial<F>,
    from_ops: &[FromOp],
    destination: &mut FieldPolynomial<F>,
) {
    for (d, from_op) in destination.iter_mut().zip(from_ops.iter()) {
        let c = unsafe { poly.as_slice().get_unchecked(from_op.from) };
        match from_op.op {
            Op::Add => {
                F::add_assign(d, *c);
            }
            Op::Sub => {
                F::sub_assign(d, *c);
            }
        }
    }
}

#[inline]
fn poly_auto_for_dimension_plus_one<F: NttField>(poly: &FieldPolynomial<F>) -> FieldPolynomial<F> {
    let mut result = poly.clone();
    result[1..]
        .iter_mut()
        .step_by(2)
        .for_each(|v| F::neg_assign(v));
    result
}

#[inline]
fn poly_auto_inplace_for_dimension_plus_one<F: NttField>(
    poly: &FieldPolynomial<F>,
    destination: &mut FieldPolynomial<F>,
) {
    for (pi, di) in poly
        .as_slice()
        .chunks_exact(2)
        .zip(destination.as_mut_slice().chunks_exact_mut(2))
    {
        di[0] = pi[0];
        di[1] = F::neg(pi[1]);
    }
}

#[inline]
fn poly_auto_add_inplace_for_dimension_plus_one<F: NttField>(
    poly: &FieldPolynomial<F>,
    destination: &mut FieldPolynomial<F>,
) {
    for (pi, di) in poly
        .as_slice()
        .chunks_exact(2)
        .zip(destination.as_mut_slice().chunks_exact_mut(2))
    {
        F::add_assign(&mut di[0], pi[0]);
        F::sub_assign(&mut di[1], pi[1]);
    }
}

#[cfg(test)]
mod tests {
    use algebra::{reduce::ReduceNeg, Field, U32FieldEval};
    use lattice::Rlwe;
    use rand::{distributions::Uniform, prelude::Distribution};

    use super::*;

    type Fp = U32FieldEval<132120577>;
    type ValT = <Fp as Field>::ValueT; // inner type
    type PolyT = FieldPolynomial<Fp>;

    const CIPHER_MODULUS: ValT = <Fp as Field>::MODULUS_VALUE; // ciphertext space
    const PLAIN_MODULUS: ValT = 8; // message space

    const LOG_N: u32 = 10;
    const N: usize = 1 << LOG_N;

    #[inline]
    fn encode(m: ValT) -> ValT {
        (m as f64 * CIPHER_MODULUS as f64 / PLAIN_MODULUS as f64).round() as ValT
    }

    #[inline]
    fn decode(c: ValT) -> ValT {
        (c as f64 * PLAIN_MODULUS as f64 / CIPHER_MODULUS as f64).round() as ValT % PLAIN_MODULUS
    }

    #[test]
    fn test_auto() {
        let mut rng = rand::thread_rng();

        let poly = PolyT::random_ternary(N, &mut rng);
        let auto_type = AutoHelper::DimensionPlusOne;
        let result = poly_auto(&poly, &auto_type);

        let flag = result
            .iter()
            .zip(poly.iter())
            .enumerate()
            .all(|(i, (&r, &p))| {
                if i % 2 == 1 {
                    r == Fp::MODULUS.reduce_neg(p)
                } else {
                    r == p
                }
            });

        assert!(flag);
    }

    #[test]
    fn test_he_auto() {
        let mut rng = rand::thread_rng();

        let ntt_table = Arc::new(Fp::generate_ntt_table(LOG_N).unwrap());
        let distr = Uniform::new(0, PLAIN_MODULUS);

        let sk = RlweSecretKey::new(
            PolyT::random_ternary(N, &mut rng),
            crate::RingSecretKeyType::Ternary,
        );
        let ntt_sk = NttRlweSecretKey::from_coeff_secret_key(&sk, &ntt_table);
        let gaussian = DiscreteGaussian::new(0.0, 3.2, Fp::MINUS_ONE).unwrap();
        let basis = NonPowOf2ApproxSignedBasis::new(Fp::MODULUS_VALUE, 4, None);

        let values: Vec<ValT> = distr.sample_iter(&mut rng).take(N).collect();
        let encoded_values = PolyT::new(values.iter().copied().map(encode).collect());

        let mut cipher =
            <Rlwe<Fp>>::generate_random_zero_sample(&ntt_sk, &gaussian, &ntt_table, &mut rng);
        *cipher.b_mut() += &encoded_values;

        let auto_key = AutoKey::new(
            &sk,
            &ntt_sk,
            N + 1,
            &basis,
            &gaussian,
            Arc::clone(&ntt_table),
            &mut rng,
        );
        let result = auto_key.automorphism(&cipher);

        let decrypted_values = (result.b()
            - ntt_table.inverse_transform_inplace(ntt_table.transform(result.a()) * &*ntt_sk))
        .into_iter()
        .map(decode)
        .collect::<Vec<u32>>();

        let flag = decrypted_values
            .iter()
            .zip(values.iter())
            .enumerate()
            .all(|(i, (&r, &p))| {
                if i % 2 == 1 {
                    (r + p) % PLAIN_MODULUS == 0
                } else {
                    r == p
                }
            });

        assert!(flag);

        let mut auto_space = AutoSpace::new(N);
        let mut poly_space = <FieldPolynomial<Fp>>::zero(N);
        let mut result = <NttRlweCiphertext<Fp>>::zero(N);
        auto_key.automorphism_ntt_inplace(&cipher, &mut auto_space, &mut poly_space, &mut result);

        let decrypted_values = (ntt_table
            .inverse_transform_inplace(result.b() - result.a().clone() * &*ntt_sk))
        .into_iter()
        .map(decode)
        .collect::<Vec<u32>>();

        let flag = decrypted_values
            .iter()
            .zip(values.iter())
            .enumerate()
            .all(|(i, (&r, &p))| {
                if i % 2 == 1 {
                    (r + p) % PLAIN_MODULUS == 0
                } else {
                    r == p
                }
            });

        assert!(flag);
    }
}
