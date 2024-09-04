use algebra::{
    derive::{DecomposableField, Field, Prime},
    DenseMultilinearExtension, Field,
};
use num_traits::Zero;
use rand::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::rc::Rc;
use std::vec;
use zkp::piop::{Lookup, LookupInstance};

#[derive(Field, DecomposableField, Prime)]
#[modulus = 132120577]
pub struct Fp32(u32);

#[derive(Field, DecomposableField, Prime)]
#[modulus = 59]
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

#[test]
fn test_trivial_range_check() {
    // prepare parameters

    let num_vars = 4;
    let block_size = 2;
    let range: usize = 6;

    // construct a trivial example

    let f0 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 1, 4, 3, 2, 3, 0, 1, 1, 3, 2, 1, 0, 4, 1, 1, 0),
    ));
    let f1 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 4, 2, 5, 3, 4, 0, 1, 4, 3, 2, 1, 0, 4, 1, 1, 3),
    ));
    let f2 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 4, 5, 1, 2, 3, 0, 1, 1, 3, 2, 1, 0, 4, 1, 1, 1),
    ));
    let f3 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 4, 5, 5, 2, 4, 0, 1, 2, 3, 2, 1, 0, 3, 1, 1, 1),
    ));
    let f4 = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 4, 1, 5, 2, 4, 0, 1, 3, 3, 2, 1, 0, 5, 1, 1, 2),
    ));

    let f_vec = vec![f0, f1, f2, f3, f4];

    let mut t_evaluations: Vec<_> = (0..range).map(|i| FF::new(i as u32)).collect();
    t_evaluations.resize(1 << num_vars, FF::zero());
    let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        t_evaluations,
    ));

    // construct instance

    let instance = LookupInstance::from_slice(&f_vec, t.clone(), block_size);
    let info = instance.info();

    // prepare fiat-shamir randomness
    let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
    let mut fs_rng_prover = ChaCha12Rng::from_seed(seed);
    let mut fs_rng_verifier = ChaCha12Rng::from_seed(seed);

    // prove

    let (proof, oracle) = Lookup::prove(&mut fs_rng_prover, &instance);

    // verify

    let subclaim = Lookup::verify(&mut fs_rng_verifier, &proof, &info);
    assert!(subclaim.verify_subclaim(f_vec, t.clone(), oracle, &info));
}

#[test]
fn test_random_range_check() {
    // prepare parameters

    let num_vars = 8;
    let block_size = 4;
    let block_num = 5;
    let residual_size = 1;
    let lookup_num = block_num * block_size + residual_size;
    let range = 59;

    let mut rng = thread_rng();
    let f_vec: Vec<Rc<DenseMultilinearExtension<Fp32>>> = (0..lookup_num)
        .map(|_| {
            let f_evaluations: Vec<FF> = (0..(1 << num_vars))
                .map(|_| FF::new(rng.gen_range(0..range)))
                .collect();
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                f_evaluations,
            ))
        })
        .collect();

    let mut t_evaluations: Vec<_> = (0..range as usize).map(|i| FF::new(i as u32)).collect();
    t_evaluations.resize(1 << num_vars, FF::zero());
    let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        t_evaluations,
    ));

    let instance = LookupInstance::from_slice(&f_vec, t.clone(), block_size);
    let info = instance.info();

    // prepare fiat-shamir randomness

    let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
    let mut fs_rng_prover = ChaCha12Rng::from_seed(seed);
    let mut fs_rng_verifier = ChaCha12Rng::from_seed(seed);

    // prove

    let (proof, oracle) = Lookup::prove(&mut fs_rng_prover, &instance);

    // verify

    let subclaim = Lookup::verify(&mut fs_rng_verifier, &proof, &info);
    let result = subclaim.verify_subclaim(f_vec, t.clone(), oracle, &info);
    assert!(result);
}
