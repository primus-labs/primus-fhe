// use algebra::{
//     derive::{DecomposableField, Field, Prime},
//     DenseMultilinearExtension, Field,
// };
// use criterion::{criterion_group, criterion_main, Criterion};
// use num_traits::Zero;
// use rand::prelude::*;
// use rand::SeedableRng;
// use rand_chacha::ChaCha12Rng;
// use std::rc::Rc;
// use std::time::Duration;
// use std::vec;
// use zkp::piop::{Lookup, LookupInstance};

// #[derive(Field, DecomposableField, Prime)]
// #[modulus = 132120577]
// pub struct Fp32(u32);

// #[derive(Field, DecomposableField, Prime)]
// #[modulus = 59]
// pub struct Fq(u32);

// // field type
// type FF = Fp32;

// pub fn criterion_benchmark(c: &mut Criterion) {
//     let num_vars = 8;
//     let block_size = 2;
//     let block_num = 20;
//     let lookup_num: usize = block_num * block_size;
//     let range = 59;

//     let mut rng = thread_rng();
//     let f_vec: Vec<Rc<DenseMultilinearExtension<Fp32>>> = (0..lookup_num)
//         .map(|_| {
//             let f_evaluations: Vec<FF> = (0..(1 << num_vars))
//                 .map(|_| FF::new(rng.gen_range(0..range)))
//                 .collect();
//             Rc::new(DenseMultilinearExtension::from_evaluations_vec(
//                 num_vars,
//                 f_evaluations,
//             ))
//         })
//         .collect();

//     let mut t_evaluations: Vec<_> = (0..range).map(FF::new).collect();
//     t_evaluations.resize(1 << num_vars, FF::zero());
//     let t = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
//         num_vars,
//         t_evaluations,
//     ));

//     let instance = LookupInstance::from_slice(&f_vec, t.clone(), block_size);
//     let info = instance.info();

//     c.bench_function(
//         &format!(
//             "rang check proving time of lookup num {}, lookup size {}, range size {}",
//             lookup_num,
//             1 << num_vars,
//             range
//         ),
//         |b| {
//             let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
//             let mut fs_rng_prover = ChaCha12Rng::from_seed(seed);
//             b.iter(|| Lookup::prove(&mut fs_rng_prover, &instance))
//         },
//     );

//     c.bench_function(
//         &format!(
//             "rang check verifying time of lookup num {}, lookup size {}, range size {}",
//             lookup_num,
//             1 << num_vars,
//             range
//         ),
//         |b| {
//             let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
//             let mut fs_rng_prover = ChaCha12Rng::from_seed(seed);
//             let (proof, oracle) = Lookup::prove(&mut fs_rng_prover, &instance);
//             b.iter(|| {
//                 let mut fs_rng_verifier = ChaCha12Rng::from_seed(seed);
//                 let subclaim = Lookup::verify(&mut fs_rng_verifier, &proof, &info);
//                 subclaim.verify_subclaim(f_vec.clone(), t.clone(), oracle.clone(), &info);
//             })
//         },
//     );
// }

// fn configure() -> Criterion {
//     Criterion::default()
//         .warm_up_time(Duration::new(5, 0))
//         .measurement_time(Duration::new(10, 0))
//         .sample_size(10)
// }

// criterion_group! {
//     name = benches;
//     config = configure();
//     targets = criterion_benchmark
// }

// criterion_main!(benches);
