use algebra::{
    derive::*, utils::Transcript, Basis, DecomposableField, DenseMultilinearExtensionBase, Field,
    FieldUniformSampler, SparsePolynomial,
};
use fhe_core::{DefaultExtendsionFieldU32x4, DefaultFieldU32};
use num_traits::{One, Zero};
use rand::prelude::*;
use rand_distr::Distribution;
use std::rc::Rc;
use std::vec;
use zkp::piop::zq_to_rq::{TransformZqtoRQ, TransformZqtoRQInstance};

#[derive(Field, DecomposableField)]
#[modulus = 512]
pub struct Fq(u32);

// field type
type FF = DefaultFieldU32;
type EF = DefaultExtendsionFieldU32x4;

macro_rules! field_vec {
    ($t:ty; $elem:expr; $n:expr)=>{
        vec![<$t>::new($elem);$n]
    };
    ($t:ty; $($x:expr),+ $(,)?) => {
        vec![$(<$t>::new($x)),+]
    }
}

// a small and trivial example
// q = 8, Q = , N = 8
// (2N/q) * a(x) = N * k(x) + r(x)
// k(x) * (1-k(x)) = 0
// (r(x) + 1)(1 - 2k(x)) = s(x)
// \sum y C(u, y) * t(y) = s(u)

// a = (0, 3, 5, 7)
// 2a = (0, 6, 10, 14)
// C = (1, 0, 0, 0, 0, 0, 0, 0)
//     (0, 0, 0, 0, 0, 0, 1, 0)
//     (0, 0, -1, 0, 0, 0, 0, 0)
//     (0, 0, 0, 0, 0, 0, -1, 0)
// k = (0, 0, 1, 1)
// r = (0, 6, 2, 6)
// s = (1, 7, -3, -7) = (1, 7, 56, 52)

#[test]
fn test_trivial_zq_to_rq() {
    let p = DefaultFieldU32::MODULUS_VALUE;
    let q = 8;
    let c_num_vars = 3;
    let base_len: u32 = 1;
    let base: FF = FF::new(2);
    let num_vars = 2;
    let bits_len: u32 = 3;

    let a = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 0, 3, 5, 7),
    ));

    let k = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 0, 0, 1, 1),
    ));

    let r = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 0, 6, 2, 6),
    ));

    let s = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 1, 7, p-3, p-7),
    ));

    let c = vec![
        Rc::new(SparsePolynomial::from_evaluations_vec(
            c_num_vars,
            vec![(0, FF::one())],
        )),
        Rc::new(SparsePolynomial::from_evaluations_vec(
            c_num_vars,
            vec![(6, FF::one())],
        )),
        Rc::new(SparsePolynomial::from_evaluations_vec(
            c_num_vars,
            vec![(2, -FF::one())],
        )),
        Rc::new(SparsePolynomial::from_evaluations_vec(
            c_num_vars,
            vec![(6, -FF::one())],
        )),
    ];

    let c_dense = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        c_num_vars + num_vars,
        field_vec!(FF; 
            1, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 1, 0,
             0, 0, p-1, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, p-1, 0),
    ));

    let tmp = r.get_decomposed_mles(base_len, bits_len);
    let r_bits = vec![&tmp];
    let instance = TransformZqtoRQInstance::from_vec(
        q,
        c.clone(),
        a.clone(),
        &k,
        &r,
        &s,
        base,
        base_len,
        bits_len,
    );
    let info = instance.info();

    let mut prover_trans = Transcript::<FF>::new();
    let mut verifier_trans = Transcript::<FF>::new();
    let prover_u: Vec<EF> = prover_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let verify_u: Vec<EF> = verifier_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);

    let proof = TransformZqtoRQ::prove(&mut prover_trans, &instance, &prover_u);
    let subclaim =
        TransformZqtoRQ::verify(&mut verifier_trans, &proof, &info.decomposed_bits_info, 3);

    assert!(subclaim.verify_subclaim(
        q,
        a,
        &c_dense,
        k.as_ref(),
        vec![r].as_ref(),
        s.as_ref(),
        &r_bits,
        &verify_u,
        &info
    ));
}

#[test]
fn test_random_zq_to_rq() {
    let mut rng = thread_rng();
    let uniform_fq = <FieldUniformSampler<Fq>>::new();
    let num_vars = 10;
    let q = FF::new(Fq::MODULUS_VALUE);
    let c_num_vars = (q.value() as usize).ilog2() as usize;
    let base_len: u32 = 3;
    let base: FF = FF::new(1 << base_len);
    let bits_len: u32 = <Basis<Fq>>::new(base_len).decompose_len() as u32;

    // generate a random instance
    let a_over_fq: Vec<_> = (0..(1 << num_vars))
        .map(|_| uniform_fq.sample(&mut rng))
        .collect();
    let mut a = Vec::new();
    let mut k = Vec::new();
    let mut r = Vec::new();
    let mut s = Vec::new();
    let mut c = Vec::new();
    let mut c_dense_matrix = Vec::new();

    a_over_fq.iter().for_each(|x| {
        let mut x = FF::new(x.value());
        a.push(x);
        x = FF::new(2) * x;
        if x >= q {
            k.push(FF::one());
            r.push(x - q);
            s.push(-(x - q + FF::one()));
            c.push(Rc::new(SparsePolynomial::from_evaluations_vec(
                c_num_vars,
                vec![((x - q).value() as usize, -FF::one())],
            )));
            let mut c_dense_row = vec![FF::zero(); q.value() as usize];
            c_dense_row[(x - q).value() as usize] = -FF::one();
            c_dense_matrix.extend(c_dense_row);
        } else {
            k.push(FF::zero());
            r.push(x);
            s.push(x + FF::one());
            c.push(Rc::new(SparsePolynomial::from_evaluations_vec(
                c_num_vars,
                vec![(x.value() as usize, FF::one())],
            )));
            let mut c_dense_row = vec![FF::zero(); q.value() as usize];
            c_dense_row[x.value() as usize] = FF::one();
            c_dense_matrix.extend(c_dense_row);
        }
    });

    let a: Rc<DenseMultilinearExtensionBase<FF>> = Rc::new(
        DenseMultilinearExtensionBase::from_evaluations_vec(num_vars, a),
    );
    let k: Rc<DenseMultilinearExtensionBase<FF>> = Rc::new(
        DenseMultilinearExtensionBase::from_evaluations_vec(num_vars, k),
    );
    let r: Rc<DenseMultilinearExtensionBase<FF>> = Rc::new(
        DenseMultilinearExtensionBase::from_evaluations_vec(num_vars, r),
    );
    let s: Rc<DenseMultilinearExtensionBase<FF>> = Rc::new(
        DenseMultilinearExtensionBase::from_evaluations_vec(num_vars, s),
    );
    let c_dense = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        num_vars + c_num_vars,
        c_dense_matrix,
    ));

    let tmp = r.get_decomposed_mles(base_len, bits_len);
    let r_bits: Vec<_> = vec![&tmp];
    let instance = TransformZqtoRQInstance::<FF>::from_vec(
        q.value() as usize,
        c.clone(),
        a.clone(),
        &k,
        &r,
        &s,
        base,
        base_len,
        bits_len,
    );
    let info = instance.info();
    let mut prover_trans = Transcript::<FF>::new();
    let mut verifier_trans = Transcript::<FF>::new();
    let prover_u: Vec<EF> = prover_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let verify_u: Vec<EF> = verifier_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);

    let proof = TransformZqtoRQ::prove(&mut prover_trans, &instance, &prover_u);
    let subclaim = TransformZqtoRQ::verify(
        &mut verifier_trans,
        &proof,
        &info.decomposed_bits_info,
        c_num_vars,
    );

    assert!(subclaim.verify_subclaim(
        q.value() as usize,
        a,
        &c_dense,
        k.as_ref(),
        vec![r].as_ref(),
        s.as_ref(),
        &r_bits,
        &verify_u,
        &info
    ));
}

#[test]
fn test_trivial_zq_to_rq_without_oracle() {
    let p = DefaultFieldU32::MODULUS_VALUE;
    let q = 8;
    let c_num_vars = 3;
    let base_len: u32 = 1;
    let base: FF = FF::new(2);
    let num_vars = 2;
    let bits_len: u32 = 3;

    let a = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 0, 3, 5, 7),
    ));

    let k = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 0, 0, 1, 1),
    ));

    let r = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 0, 6, 2, 6),
    ));

    let s = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 1, 7, p-3, p-7),
    ));

    let c_sparse = vec![
        Rc::new(SparsePolynomial::from_evaluations_vec(
            c_num_vars,
            vec![(0, FF::one())],
        )),
        Rc::new(SparsePolynomial::from_evaluations_vec(
            c_num_vars,
            vec![(6, FF::one())],
        )),
        Rc::new(SparsePolynomial::from_evaluations_vec(
            c_num_vars,
            vec![(2, -FF::one())],
        )),
        Rc::new(SparsePolynomial::from_evaluations_vec(
            c_num_vars,
            vec![(6, -FF::one())],
        )),
    ];

    let tmp = r.get_decomposed_mles(base_len, bits_len);
    let r_bits = vec![&tmp];
    let instance = TransformZqtoRQInstance::from_vec(
        q,
        c_sparse.clone(),
        a.clone(),
        &k,
        &r,
        &s,
        base,
        base_len,
        bits_len,
    );
    let info = instance.info();
    let mut prover_trans = Transcript::<FF>::new();
    let mut verifier_trans = Transcript::<FF>::new();
    let prover_u: Vec<EF> = prover_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let verify_u: Vec<EF> = verifier_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let proof = TransformZqtoRQ::prove(&mut prover_trans, &instance, &prover_u);
    let subclaim =
        TransformZqtoRQ::verify(&mut verifier_trans, &proof, &info.decomposed_bits_info, 3);

    assert!(subclaim.verify_subclaim_without_oracle(
        q,
        a,
        &c_sparse,
        k.as_ref(),
        vec![r].as_ref(),
        s.as_ref(),
        &r_bits,
        &verify_u,
        &info
    ));
}

#[test]
fn test_random_zq_to_rq_without_oracle() {
    let mut rng = thread_rng();
    let uniform_fq = <FieldUniformSampler<Fq>>::new();
    let num_vars = 10;
    let q = FF::new(Fq::MODULUS_VALUE);
    let c_num_vars = (q.value() as usize).ilog2() as usize;
    let base_len: u32 = 3;
    let base: FF = FF::new(1 << base_len);
    let bits_len: u32 = <Basis<Fq>>::new(base_len).decompose_len() as u32;

    // generate a random instance
    let a_over_fq: Vec<_> = (0..(1 << num_vars))
        .map(|_| uniform_fq.sample(&mut rng))
        .collect();
    let mut a = Vec::new();
    let mut k = Vec::new();
    let mut r = Vec::new();
    let mut s = Vec::new();
    let mut c_sparse = Vec::new();

    a_over_fq.iter().for_each(|x| {
        let mut x = FF::new(x.value());
        a.push(x);
        x = FF::new(2) * x;
        if x >= q {
            k.push(FF::one());
            r.push(x - q);
            s.push(-(x - q + FF::one()));
            c_sparse.push(Rc::new(SparsePolynomial::from_evaluations_vec(
                c_num_vars,
                vec![((x - q).value() as usize, -FF::one())],
            )));
        } else {
            k.push(FF::zero());
            r.push(x);
            s.push(x + FF::one());
            c_sparse.push(Rc::new(SparsePolynomial::from_evaluations_vec(
                c_num_vars,
                vec![(x.value() as usize, FF::one())],
            )));
        }
    });

    let a: Rc<DenseMultilinearExtensionBase<FF>> = Rc::new(
        DenseMultilinearExtensionBase::from_evaluations_vec(num_vars, a),
    );
    let k: Rc<DenseMultilinearExtensionBase<FF>> = Rc::new(
        DenseMultilinearExtensionBase::from_evaluations_vec(num_vars, k),
    );
    let r: Rc<DenseMultilinearExtensionBase<FF>> = Rc::new(
        DenseMultilinearExtensionBase::from_evaluations_vec(num_vars, r),
    );
    let s: Rc<DenseMultilinearExtensionBase<FF>> = Rc::new(
        DenseMultilinearExtensionBase::from_evaluations_vec(num_vars, s),
    );

    let tmp = r.get_decomposed_mles(base_len, bits_len);
    let r_bits: Vec<_> = vec![&tmp];
    let instance = TransformZqtoRQInstance::<FF>::from_vec(
        q.value() as usize,
        c_sparse.clone(),
        a.clone(),
        &k,
        &r,
        &s,
        base,
        base_len,
        bits_len,
    );
    let info = instance.info();
    let mut prover_trans = Transcript::<FF>::new();
    let mut verifier_trans = Transcript::<FF>::new();
    let prover_u: Vec<EF> = prover_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let verify_u: Vec<EF> = verifier_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);

    let proof = TransformZqtoRQ::prove(&mut prover_trans, &instance, &prover_u);
    let subclaim = TransformZqtoRQ::verify(
        &mut verifier_trans,
        &proof,
        &info.decomposed_bits_info,
        c_num_vars,
    );

    assert!(subclaim.verify_subclaim_without_oracle(
        q.value() as usize,
        a,
        &c_sparse,
        k.as_ref(),
        vec![r].as_ref(),
        s.as_ref(),
        &r_bits,
        &verify_u,
        &info
    ));
}
