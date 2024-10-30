// use algebra::Basis;
// use algebra::{
//     derive::{DecomposableField, Field, Prime},
//     DecomposableField, DenseMultilinearExtension, Field, FieldUniformSampler,
// };
// // use protocol::bit_decomposition::{BitDecomposition, DecomposedBits};
// use criterion::{criterion_group, criterion_main, Criterion};
// use rand::prelude::*;
// use rand_distr::Distribution;
// use std::rc::Rc;
// use std::time::Duration;
// use std::vec;
// use zkp::piop::{BitDecomposition, DecomposedBits};

// #[derive(Field, DecomposableField, Prime)]
// #[modulus = 132120577]
// pub struct Fp32(u32);

// #[derive(Field, DecomposableField, Prime)]
// #[modulus = 59]
// pub struct Fq(u32);

// // field type
// type FF = Fp32;

// pub fn criterion_benchmark(c: &mut Criterion) {
//     let lookup_num = 20;

//     let num_vars = 8;

//     let base_len: u32 = 3;
//     let base: FF = FF::new(1 << base_len);
//     let bits_len: u32 = <Basis<Fq>>::new(base_len).decompose_len() as u32;

//     let mut rng = thread_rng();
//     let uniform_fq = <FieldUniformSampler<Fq>>::new();
//     let uniform_ff = <FieldUniformSampler<FF>>::new();

//     let d: Vec<Rc<DenseMultilinearExtension<FF>>> = (0..lookup_num)
//         .map(|_| {
//             Rc::new(DenseMultilinearExtension::from_evaluations_vec(
//                 num_vars,
//                 (0..(1 << num_vars))
//                     .map(|_| FF::new(uniform_fq.sample(&mut rng).value()))
//                     .collect(),
//             ))
//         })
//         .collect();

//     c.bench_function(
//         &format!("prove lookup_num {} lookup size {}", lookup_num, num_vars),
//         |b| {
//             b.iter(|| {
//                 let d_bits: Vec<_> = d
//                     .iter()
//                     .map(|x| x.get_decomposed_mles(base_len, bits_len))
//                     .collect();
//                 let _: Vec<_> = d_bits.iter().collect();

//                 let mut decomposed_bits = DecomposedBits::new(base, base_len, bits_len, num_vars);
//                 for d_instance in d_bits.iter() {
//                     decomposed_bits.add_decomposed_bits_instance(d_instance);
//                 }

//                 let _ = decomposed_bits.info();

//                 let u: Vec<_> = (0..num_vars).map(|_| uniform_ff.sample(&mut rng)).collect();
//                 BitDecomposition::prove(&decomposed_bits, &u);
//             })
//         },
//     );

//     c.bench_function(
//         &format!("verify lookup_num {} lookup size {}", lookup_num, num_vars),
//         |b| {
//             let d_bits: Vec<_> = d
//                 .iter()
//                 .map(|x| x.get_decomposed_mles(base_len, bits_len))
//                 .collect();
//             let d_bits_ref: Vec<_> = d_bits.iter().collect();

//             let mut decomposed_bits = DecomposedBits::new(base, base_len, bits_len, num_vars);
//             for d_instance in d_bits.iter() {
//                 decomposed_bits.add_decomposed_bits_instance(d_instance);
//             }

//             let decomposed_bits_info = decomposed_bits.info();

//             let u: Vec<_> = (0..num_vars).map(|_| uniform_ff.sample(&mut rng)).collect();
//             let proof = BitDecomposition::prove(&decomposed_bits, &u);
//             b.iter(|| {
//                 let subclaim = BitDecomposition::verifier(&proof, &decomposed_bits_info);
//                 assert!(subclaim.verify_subclaim(&d, &d_bits_ref, &u, &decomposed_bits_info));
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
