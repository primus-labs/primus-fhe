use std::sync::Arc;

use algebra::{
    decompose::NonPowOf2ApproxSignedBasis, polynomial::FieldPolynomial, random::DiscreteGaussian,
    Field, NttField,
};
use criterion::{criterion_group, criterion_main, Criterion};
use fhe_core::{NttRlweSecretKey, RingSecretKeyType, RlweCiphertext, RlweSecretKey, TraceKey};
use rand::{distributions::Uniform, prelude::Distribution};

type FieldT = algebra::U32FieldEval<132120577>;
type ValT = <FieldT as Field>::ValueT; // inner type
type PolyT = FieldPolynomial<FieldT>;

const CIPHER_MODULUS: ValT = FieldT::MODULUS_VALUE; // ciphertext space
const PLAIN_MODULUS: ValT = 8; // message space

const LOG_N: u32 = 10;
const N: usize = 1 << LOG_N;

#[inline]
fn encode(m: ValT) -> ValT {
    (m as f64 * CIPHER_MODULUS as f64 / PLAIN_MODULUS as f64).round() as ValT
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let ntt_table = Arc::new(FieldT::generate_ntt_table(LOG_N).unwrap());

    let mut csrng = rand::thread_rng();

    let gaussian = DiscreteGaussian::new(0.0, 3.2, FieldT::MINUS_ONE).unwrap();
    let distr = Uniform::new(0, PLAIN_MODULUS);

    let sk = RlweSecretKey::new(
        PolyT::random_ternary(N, &mut csrng),
        RingSecretKeyType::Ternary,
    );
    let ntt_sk = NttRlweSecretKey::from_coeff_secret_key(&sk, &ntt_table);

    let basis = NonPowOf2ApproxSignedBasis::new(FieldT::MODULUS_VALUE, 4, None);

    let trace_key = TraceKey::new(
        &sk,
        &ntt_sk,
        &basis,
        gaussian,
        Arc::clone(&ntt_table),
        &mut csrng,
    );

    let mut values: Vec<ValT> = distr.sample_iter(&mut csrng).take(N).collect();
    let encoded_values = PolyT::new(values.iter().copied().map(encode).collect());

    let mut cipher = <RlweCiphertext<FieldT>>::generate_random_zero_sample(
        &ntt_sk, gaussian, &ntt_table, &mut csrng,
    );
    *cipher.b_mut() += &encoded_values;

    let mut destination = <RlweCiphertext<FieldT>>::zero(N);

    c.bench_function(&format!("trace {}", N), |b| {
        b.iter(|| trace_key.trace_inplace(&cipher, &mut destination))
    });

    c.bench_function(&format!("expand coefficients {}", N), |b| {
        b.iter(|| trace_key.expand_coefficients(&cipher))
    });

    c.bench_function(&format!("par expand coefficients {}", N), |b| {
        b.iter(|| trace_key.par_expand_coefficients(&cipher))
    });

    let op_len = 128;

    values[op_len..].fill(0);
    let encoded_values = PolyT::new(values.iter().copied().map(encode).collect());

    let mut cipher = <RlweCiphertext<FieldT>>::generate_random_zero_sample(
        &ntt_sk, gaussian, &ntt_table, &mut csrng,
    );
    *cipher.b_mut() += &encoded_values;

    c.bench_function(&format!("expand partial coefficients {}", N), |b| {
        b.iter(|| trace_key.expand_partial_coefficients(&cipher, op_len))
    });

    c.bench_function(&format!("par expand partial coefficients {}", N), |b| {
        b.iter(|| trace_key.par_expand_partial_coefficients(&cipher, op_len))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
