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
pub enum AssignOp {
    Add,
    Sub,
}

/// This defines the operation and the rotation index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElementAutoOp {
    assign_op: AssignOp,
    to_index: usize,
}

#[derive(Debug, Clone)]
pub enum AutoType {
    DimensionPlusOne,
    Others(Vec<ElementAutoOp>),
    One,
}

/// Automorphism key
pub struct AutoKey<F: NttField> {
    degree: usize,
    auto_type: AutoType,
    key: NttGadgetRlwe<F>,
    pub(crate) ntt_table: Arc<<F as NttField>::Table>,
}

impl<F: NttField> Clone for AutoKey<F> {
    fn clone(&self) -> Self {
        Self {
            degree: self.degree,
            auto_type: self.auto_type.clone(),
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
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: Arc<<F as NttField>::Table>,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let rlwe_dimension = secret_key.coeff_count();
        assert!(degree & 1 == 1 && Xgcd::gcd(degree, rlwe_dimension << 1) == 1);

        let auto_type;
        let key = if degree.is_one() {
            auto_type = AutoType::One;
            NttGadgetRlwe::generate_random_neg_secret_sample(
                ntt_secret_key,
                basis,
                gaussian,
                &ntt_table,
                rng,
            )
        } else {
            auto_type = if degree == rlwe_dimension + 1 {
                AutoType::DimensionPlusOne
            } else {
                AutoType::Others(generate_auto_ops(degree, rlwe_dimension))
            };

            let p_auto = poly_auto(secret_key, &auto_type);
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
            auto_type,
            ntt_table,
            degree,
        }
    }

    /// Performs automorphism on the given RLWE ciphertext.
    #[inline]
    pub fn automorphism(&self, ciphertext: &RlweCiphertext<F>) -> RlweCiphertext<F> {
        if let AutoType::One = self.auto_type {
            ciphertext.clone()
        } else {
            let a = poly_auto(ciphertext.a(), &self.auto_type);

            let mut result = self
                .key
                .mul_polynomial(&a, &self.ntt_table)
                .to_rlwe(&self.ntt_table);

            poly_auto_add_inplace(ciphertext.b(), &self.auto_type, result.b_mut());

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
        poly_auto_inplace(ciphertext.a(), &self.auto_type, destination.a_mut());

        self.key.mul_polynomial_inplace(
            destination.a(),
            &self.ntt_table,
            &mut auto_space.decompose_space,
            &mut auto_space.ntt_rlwe_space,
        );

        auto_space
            .ntt_rlwe_space
            .inverse_transform_inplace(&self.ntt_table, destination);

        poly_auto_add_inplace(ciphertext.b(), &self.auto_type, destination.b_mut());
    }

    /// Performs automorphism on the given RLWE ciphertext in place.
    pub fn automorphism_ntt_inplace(
        &self,
        ciphertext: &RlweCiphertext<F>,
        auto_space: &mut AutoSpace<F>,
        poly_space: &mut FieldPolynomial<F>,
        destination: &mut NttRlweCiphertext<F>,
    ) {
        poly_auto_inplace(ciphertext.a(), &self.auto_type, poly_space);

        self.key.mul_polynomial_inplace(
            poly_space,
            &self.ntt_table,
            &mut auto_space.decompose_space,
            &mut auto_space.ntt_rlwe_space,
        );

        poly_auto_inplace(ciphertext.b(), &self.auto_type, poly_space);

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
fn generate_auto_ops(degree: usize, dimension: usize) -> Vec<ElementAutoOp> {
    let twice_dimension = dimension << 1;
    let modulus = <PowOf2Modulus<usize>>::new(twice_dimension);
    (0..dimension)
        .map(|i| {
            let to = modulus.reduce_mul(i, degree);
            if to < dimension {
                ElementAutoOp {
                    assign_op: AssignOp::Add,
                    to_index: to,
                }
            } else {
                ElementAutoOp {
                    assign_op: AssignOp::Sub,
                    to_index: to - dimension,
                }
            }
        })
        .collect()
}

#[inline]
fn poly_auto<F: NttField>(poly: &FieldPolynomial<F>, auto_type: &AutoType) -> FieldPolynomial<F> {
    let dimension = poly.coeff_count();
    match auto_type {
        AutoType::DimensionPlusOne => {
            let mut res = FieldPolynomial::zero(dimension);
            poly_auto_inplace_for_dimension_plus_one(poly, &mut res);
            res
        }
        AutoType::Others(auto_ops) => {
            let mut res = FieldPolynomial::zero(dimension);
            poly_auto_add_inplace_for_others(poly, auto_ops, &mut res);
            res
        }
        AutoType::One => poly.clone(),
    }
}

#[inline]
fn poly_auto_inplace<F: NttField>(
    poly: &FieldPolynomial<F>,
    auto_type: &AutoType,
    destination: &mut FieldPolynomial<F>,
) {
    match auto_type {
        AutoType::DimensionPlusOne => {
            poly_auto_inplace_for_dimension_plus_one(poly, destination);
        }
        AutoType::Others(auto_ops) => {
            destination.set_zero();
            poly_auto_add_inplace_for_others(poly, auto_ops, destination);
        }
        AutoType::One => poly_auto_inplace_for_one(poly, destination),
    }
}

#[inline]
fn poly_auto_add_inplace<F: NttField>(
    poly: &FieldPolynomial<F>,
    auto_type: &AutoType,
    destination: &mut FieldPolynomial<F>,
) {
    match auto_type {
        AutoType::DimensionPlusOne => {
            poly_auto_add_inplace_for_dimension_plus_one(poly, destination);
        }
        AutoType::Others(auto_ops) => {
            poly_auto_add_inplace_for_others(poly, auto_ops, destination);
        }
        AutoType::One => poly_auto_add_inplace_for_one(poly, destination),
    }
}

#[inline]
fn poly_auto_add_inplace_for_others<F: NttField>(
    poly: &FieldPolynomial<F>,
    auto_ops: &[ElementAutoOp],
    destination: &mut FieldPolynomial<F>,
) {
    for (&c, op) in poly.iter().zip(auto_ops.iter()) {
        match op.assign_op {
            AssignOp::Add => {
                F::add_assign(&mut destination[op.to_index], c);
            }
            AssignOp::Sub => {
                F::sub_assign(&mut destination[op.to_index], c);
            }
        }
    }
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
        let auto_type = AutoType::DimensionPlusOne;
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
            <Rlwe<Fp>>::generate_random_zero_sample(&ntt_sk, gaussian, &ntt_table, &mut rng);
        *cipher.b_mut() += &encoded_values;

        let auto_key = AutoKey::new(
            &sk,
            &ntt_sk,
            N + 1,
            &basis,
            gaussian,
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

    #[test]
    fn test_auto_index() {
        let log_step = 3;
        let step = 1 << log_step;
        let degree = 2usize.pow(10 - log_step) + 1;
        // let degree = 1023;
        let auto_ops = generate_auto_ops(degree, N);
        let mut tags = vec![(false, 0); N];
        for (i, auto_op) in auto_ops.iter().enumerate() {
            if tags[auto_op.to_index].0 {
                println!("{:4} vs {:4}", tags[auto_op.to_index].1, i);
                panic!("err");
            } else {
                tags[auto_op.to_index] = (true, i);
            }
        }

        println!("\n---------");
        for i in 0..step {
            for auto_op in auto_ops[i..].iter().step_by(step) {
                print!("{},", auto_op.to_index);
            }
            println!("\n---------");
            for auto_op in auto_ops[i..].iter().step_by(step) {
                print!("{:?},", auto_op.assign_op);
            }
            println!("\n---------");
        }

        // let mut inv_auto_ops = vec![(0, AssignOp::Add); 1024];
        // for (i, auto_op) in auto_ops.iter().enumerate() {
        //     inv_auto_ops[auto_op.to_index] = (i, auto_op.assign_op);
        // }

        // println!("\n---------");
        // let step = 1 << log_step;
        // for i in 0..step {
        //     for auto_op in inv_auto_ops[i..].iter().step_by(step) {
        //         print!("{},", auto_op.0);
        //     }
        //     println!("\n---------");
        //     for auto_op in inv_auto_ops[i..].iter().step_by(step) {
        //         print!("{:?},", auto_op.1);
        //     }
        //     println!("\n---------");
        // }
    }
}
