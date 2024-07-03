use algebra::{
    derive::{Field, Prime, NTT},
    Basis, DenseMultilinearExtension, Field, FieldUniformSampler, SparsePolynomial,
};
use rand::prelude::*;
use rand_distr::Distribution;
use std::rc::Rc;
use std::vec;
use zkp::piop::zq_to_rq::{TransformZqtoRQ, TransformZqtoRQInstance};

#[derive(Field)]
#[modulus = 132120577]
pub struct Fp32(u32);

#[derive(Field)]
#[modulus = 512]
pub struct Fq(u32);

// field type
type FF = Fp32;


macro_rules! field_vec {
    ($t:ty; $elem:expr; $n:expr)=>{
        vec![<$t>::new($elem);$n]
    };
    ($t:ty; $($x:expr),+ $(,)?) => {
        vec![$(<$t>::new($x)),+]
    }
}


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


fn mainn() {
    let mut rng = thread_rng();
    let sampler = <FieldUniformSampler<FF>>::new();
    let p = 132120577;
    let q = 8;
    let c_num_vars = 3;
    let base_len: u32 = 1;
    let base: FF = FF::new(2);
    let num_vars = 2;
    let bits_len: u32 = 3;
    let a =
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 0, 3, 5, 7),
        ));

    let k = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 0, 0, 1, 1),
    ));

    let r = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 0, 6, 2, 6),
    ));

    let s = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 1, 7, p-3, p-7)
    ));
    
    let c = vec![Rc::new(SparsePolynomial::from_evaluations_vec(c_num_vars, vec![ (0, FF::ONE)])),
    Rc::new(SparsePolynomial::from_evaluations_vec(c_num_vars, vec![ (6, FF::ONE)])),
    Rc::new(SparsePolynomial::from_evaluations_vec(c_num_vars, vec![ (2, -FF::ONE)])),
    Rc::new(SparsePolynomial::from_evaluations_vec(c_num_vars, vec![ (6, -FF::ONE)]))];

    let c_sparse = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        c_num_vars + num_vars,
        field_vec!(FF; 
            1, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 1, 0,
             0, 0, p-1, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, p-1, 0),
    ));
    println!("ok");

    let r_bits = vec![r.get_decomposed_mles(base_len, bits_len)];

    let instance = TransformZqtoRQInstance::from_vec(q, q, c.clone(), a.clone(), &k,&r,&s,base, base_len, bits_len);
    let info = instance.info();
    let u: Vec<_> = (0..num_vars).map(|_| sampler.sample(&mut rng)).collect();
    let proof = TransformZqtoRQ::prove(&instance, &u);
    let subclaim = TransformZqtoRQ::verify(&proof, &info.decomposed_bits_info, 3);
    println!("{:?}",subclaim.verify_subclaim(q, c, &c_sparse, a, k.as_ref(), vec![r].as_ref(), s.as_ref(), &r_bits, &u, &info));
}





fn main() {
    let mut rng = thread_rng();
    let uniform_fq = <FieldUniformSampler<Fq>>::new();
    let uniform_fp = <FieldUniformSampler<FF>>::new();
    let num_vars = 10;
    let q = FF::new(Fq::MODULUS_VALUE);
    let c_num_vars = q.get().ilog2();
    let base_len: u32 = 3;
    let base: FF = FF::new(1 << base_len);
    let bits_len: u32 = <Basis<Fq>>::new(base_len).decompose_len() as u32;

    // Addition in Zq
    let aa: Vec<_> = (0..(1 << num_vars))
        .map(|_| uniform_fq.sample(&mut rng))
        .collect();
    let mut a = Vec::new();
    let mut k = Vec::new();
    let mut r = Vec::new();
    let mut s = Vec::new();
    let mut c = Vec::new();
    let mut c_sp = Vec::new();

    aa.iter().for_each(|x| {
        let mut x = FF::new(x.get());
        a.push(x);
        x = FF::new(2) * x;
        if x >= q {
            k.push(FF::ONE);
            r.push(x - q);
            s.push(-(x - q + FF::ONE));
            c.push(Rc::new(SparsePolynomial::from_evaluations_vec(c_num_vars as usize, vec![((x - q).get() as usize, -FF::ONE)])));
            let mut cc = vec![FF::ZERO; q.get() as usize];
            cc[(x - q).get() as usize] = -FF::ONE;
            c_sp.extend(cc);
        } else {
            k.push(FF::ZERO);
            r.push(x);
            s.push((x + FF::ONE));
            c.push(Rc::new(SparsePolynomial::from_evaluations_vec(c_num_vars as usize, vec![(x.get() as usize, FF::ONE)])));
            let mut cc = vec![FF::ZERO; q.get() as usize];
            cc[x.get() as usize] = FF::ONE;
            c_sp.extend(cc);
        }
    });

    let a: Rc<DenseMultilinearExtension<FF>> = Rc::new(DenseMultilinearExtension::from_evaluations_vec(num_vars, a));
    let k: Rc<DenseMultilinearExtension<FF>> = Rc::new(DenseMultilinearExtension::from_evaluations_vec(num_vars, k));
    let r: Rc<DenseMultilinearExtension<FF>> = Rc::new(DenseMultilinearExtension::from_evaluations_vec(num_vars, r));
    let s: Rc<DenseMultilinearExtension<FF>> = Rc::new(DenseMultilinearExtension::from_evaluations_vec(num_vars, s));
    let c_sparse = Rc::new(DenseMultilinearExtension::from_evaluations_vec(num_vars + c_num_vars as usize, c_sp));


    // let (k, r, s): (Vec<_>, Vec<_>, Vec<_>) = a.iter().map(|x| {
    //     if x >= q {
    //         (FF(1), x - q, x - q + FF::ONE)
    //     } else {
    //         (FF(0), *x, -(*x + FF::ONE))
    //     }
    // }).unzip3();


    // decompose bits of every element in a, b, c
    let r_bits: Vec<_> = vec![r.get_decomposed_mles(base_len, bits_len)];

    let instance = TransformZqtoRQInstance::<FF>::from_vec(q.get() as usize, q.get() as usize, c.clone(), a.clone(), &k,&r,&s,base, base_len, bits_len);
    let info = instance.info();
    let u: Vec<_> = (0..num_vars).map(|_| uniform_fp.sample(&mut rng)).collect();
    let proof = TransformZqtoRQ::prove(&instance, &u);
    let subclaim = TransformZqtoRQ::verify(&proof, &info.decomposed_bits_info, c_num_vars as usize);
    println!("{:?}",subclaim.verify_subclaim(q.get() as usize, c, &c_sparse, a, k.as_ref(), vec![r].as_ref(), s.as_ref(), &r_bits, &u, &info));
}
