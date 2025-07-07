// cargo bench -p fhe_core --bench rlwe_mul_rgsw
// cargo +nightly bench -p fhe_core --features="nightly" --bench rlwe_mul_rgsw

use std::sync::Arc;

use algebra::{
    decompose::NonPowOf2ApproxSignedBasis,
    polynomial::{FieldNttPolynomial, FieldPolynomial},
    random::DiscreteGaussian,
    Field, NttField,
};
use criterion::{criterion_group, criterion_main, Criterion};
use fhe_core::{NttRlweSecretKey, RingSecretKeyType, RlweCiphertext, RlweSecretKey};
use lattice::{
    utils::{NttRlweSpace, PolyDecomposeSpace},
    NttRgsw, NttRlwe,
};
use rand::{distributions::Uniform, prelude::Distribution};

type FieldT = algebra::U64FieldEval<1125899906826241>;
type ValT = <FieldT as Field>::ValueT; // inner type
type PolyT = FieldPolynomial<FieldT>;

const CIPHER_MODULUS: ValT = FieldT::MODULUS_VALUE; // ciphertext space
const PLAIN_MODULUS: ValT = 8; // message space

const LOG_N: u32 = 11;
const N: usize = 1 << LOG_N;

const TC: usize = 8; // threads count

#[inline]
fn encode(m: ValT) -> ValT {
    (m as f64 * CIPHER_MODULUS as f64 / PLAIN_MODULUS as f64).round() as ValT
}

pub fn criterion_benchmark(c: &mut Criterion) {
    rayon::ThreadPoolBuilder::new()
        .num_threads(TC)
        .build_global()
        .unwrap();

    let ntt_table = Arc::new(FieldT::generate_ntt_table(LOG_N).unwrap());

    let mut rng = rand::thread_rng();

    let gaussian = DiscreteGaussian::new(0.0, 3.2, FieldT::MINUS_ONE).unwrap();
    let distr = Uniform::new(0, PLAIN_MODULUS);

    let sk = RlweSecretKey::new(
        PolyT::random_ternary(N, &mut rng),
        RingSecretKeyType::Ternary,
    );
    let ntt_sk = NttRlweSecretKey::from_coeff_secret_key(&sk, &ntt_table);

    let basis = NonPowOf2ApproxSignedBasis::new(FieldT::MODULUS_VALUE, 7, None);
    let l = basis.decompose_length();
    println!("decompose length: {}", l);

    let rgsw = <NttRgsw<FieldT>>::generate_random_zero_sample(
        &ntt_sk, &basis, gaussian, &ntt_table, &mut rng,
    );

    let values: Vec<ValT> = distr.sample_iter(&mut rng).take(N).collect();
    let encoded_values = PolyT::new(values.iter().copied().map(encode).collect());

    let mut cipher = <RlweCiphertext<FieldT>>::generate_random_zero_sample(
        &ntt_sk, gaussian, &ntt_table, &mut rng,
    );
    *cipher.b_mut() += &encoded_values;

    let decompose_space = &mut PolyDecomposeSpace::new(N);
    let median = &mut NttRlweSpace::new(N);
    let destination = &mut RlweCiphertext::zero(N);

    c.bench_function("rlwe mul rgsw", |b| {
        b.iter(|| {
            cipher.mul_ntt_rgsw_inplace(&rgsw, &ntt_table, decompose_space, median, destination)
        })
    });

    let adjust_polys_0 = &mut FieldPolynomial::zero(N);
    let adjust_polys_1 = &mut FieldPolynomial::zero(N);
    let carries = &mut vec![false; 2 * N];
    let decompose_polys = &mut vec![FieldNttPolynomial::zero(N); l * 2];
    let wide_destination = &mut vec![NttRlwe::zero(N); l * 2];

    c.bench_function("rlwe mul rgsw multi thread 2", |b| {
        b.iter(|| {
            cipher.mul_ntt_rgsw_inplace_mt(
                &rgsw,
                &ntt_table,
                adjust_polys_0,
                adjust_polys_1,
                carries,
                decompose_polys,
                wide_destination,
                median,
                destination,
            )
        })
    });

    c.bench_function("inverse ntt", |b| {
        b.iter(|| median.inverse_transform_inplace(&ntt_table, destination))
    });

    c.bench_function("acc", |b| {
        b.iter(|| {
            let median = &mut *median;
            let _median = wide_destination.iter().fold(median, |acc, x| {
                acc.add_assign_element_wise(x);
                acc
            });
        })
    });

    c.bench_function("decompose", |b| {
        b.iter(|| {
            cipher
                .a()
                .init_adjust_poly_carries(&basis, carries, adjust_polys_0);
            basis
                .decompose_iter()
                .zip(decompose_polys.iter_mut())
                .for_each(|(once_decompose, decompose_poly)| {
                    adjust_polys_0.approx_signed_decompose(
                        once_decompose,
                        carries,
                        decompose_poly.as_mut_slice(),
                    );
                });
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
