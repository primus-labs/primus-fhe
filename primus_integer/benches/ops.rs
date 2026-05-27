#![cfg_attr(feature = "simd", feature(portable_simd))]

use std::hint::black_box;
#[cfg(feature = "simd")]
use std::simd::Simd;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_integer::{CarryingMul, DivRemScalar, WideningMul};
use rand::distr::Distribution;

type ValueT = u32;
const N: usize = 8192;
#[cfg(feature = "simd")]
const M: usize = 8;

pub fn criterion_benchmark(c: &mut Criterion) {
    // Low-MSB inputs: `[0, MAX>>2)` keeps `a*b + c` from wrapping into the
    // high-bit region.
    let distr = rand::distr::Uniform::new(0, ValueT::MAX >> 2).unwrap();
    // High-MSB inputs: `[MAX>>1, MAX]` exercises the carry-out path for
    // carrying ops and the high-quotient path for division.
    let distr_msb = rand::distr::Uniform::new(ValueT::MAX >> 1, ValueT::MAX).unwrap();
    let mut rng = rand::rng();

    let a_vec = distr.sample_iter(&mut rng).take(N).collect::<Vec<ValueT>>();
    let b_vec = distr.sample_iter(&mut rng).take(N).collect::<Vec<ValueT>>();
    let c_vec = distr.sample_iter(&mut rng).take(N).collect::<Vec<ValueT>>();
    let a_msb_vec = distr_msb
        .sample_iter(&mut rng)
        .take(N)
        .collect::<Vec<ValueT>>();
    let b_msb_vec = distr_msb
        .sample_iter(&mut rng)
        .take(N)
        .collect::<Vec<ValueT>>();
    let mut h_vec = vec![0; N];
    let mut l_vec = vec![0; N];

    c.bench_function(&format!("Primitive Widening Mul {N}"), |b| {
        b.iter(|| {
            black_box(&a_vec)
                .iter()
                .zip(black_box(&b_vec).iter())
                .zip(black_box(&mut h_vec))
                .zip(black_box(&mut l_vec))
                .for_each(|(((&a, &b), h), l)| {
                    let (x, y) = WideningMul::widening_mul(a, b);
                    *h = y;
                    *l = x;
                })
        })
    });

    c.bench_function(&format!("Primitive Widening Mul MSB {N}"), |b| {
        b.iter(|| {
            black_box(&a_msb_vec)
                .iter()
                .zip(black_box(&b_msb_vec).iter())
                .zip(black_box(&mut h_vec))
                .zip(black_box(&mut l_vec))
                .for_each(|(((&a, &b), h), l)| {
                    let (x, y) = WideningMul::widening_mul(a, b);
                    *h = y;
                    *l = x;
                })
        })
    });

    #[cfg(feature = "simd")]
    c.bench_function(&format!("Simd Widening Mul {N}"), |b| {
        b.iter(|| {
            let (a_arrs, _) = black_box(&a_vec).as_chunks::<M>();
            let (b_arrs, _) = black_box(&b_vec).as_chunks::<M>();
            let (h_arrs, _) = black_box(&mut h_vec).as_chunks_mut::<M>();
            let (l_arrs, _) = black_box(&mut l_vec).as_chunks_mut::<M>();
            a_arrs
                .iter()
                .zip(b_arrs.iter())
                .zip(h_arrs.iter_mut())
                .zip(l_arrs.iter_mut())
                .for_each(|(((a, b), h), l)| {
                    let a_simd = Simd::<ValueT, M>::from_array(*a);
                    let b_simd = Simd::<ValueT, M>::from_array(*b);
                    let (t, u) = WideningMul::widening_mul(a_simd, b_simd);
                    *h = t.to_array();
                    *l = u.to_array();
                });
        })
    });

    c.bench_function(&format!("Primitive Carrying Mul {N}"), |b| {
        b.iter(|| {
            black_box(&a_vec)
                .iter()
                .zip(black_box(&b_vec).iter())
                .zip(black_box(&c_vec).iter())
                .zip(black_box(&mut h_vec))
                .zip(black_box(&mut l_vec))
                .for_each(|((((&a, &b), &c), h), l)| {
                    let (t, u) = CarryingMul::carrying_mul(a, b, c);
                    *h = u;
                    *l = t;
                })
        })
    });

    #[cfg(feature = "simd")]
    c.bench_function(&format!("Simd Carrying Mul {N}"), |b| {
        b.iter(|| {
            let (a_arrs, _) = black_box(&a_vec).as_chunks::<M>();
            let (b_arrs, _) = black_box(&b_vec).as_chunks::<M>();
            let (c_arrs, _) = black_box(&c_vec).as_chunks::<M>();
            let (h_arrs, _) = black_box(&mut h_vec).as_chunks_mut::<M>();
            let (l_arrs, _) = black_box(&mut l_vec).as_chunks_mut::<M>();

            a_arrs
                .iter()
                .zip(b_arrs.iter())
                .zip(c_arrs.iter())
                .zip(h_arrs.iter_mut())
                .zip(l_arrs.iter_mut())
                .for_each(|((((a, b), c), h), l)| {
                    let a_simd = Simd::<ValueT, M>::from_array(*a);
                    let b_simd = Simd::<ValueT, M>::from_array(*b);
                    let c_simd = Simd::<ValueT, M>::from_array(*c);
                    let (t, u) = CarryingMul::carrying_mul(a_simd, b_simd, c_simd);
                    *h = u.to_array();
                    *l = t.to_array();
                });
        })
    });

    c.bench_function("DivRemScalar", |b| {
        b.iter(|| {
            let mut quotient = [0; 3];
            let _ = DivRemScalar::div_rem_scalar(
                black_box(&[0, 0, 1u32]),
                black_box(132120577),
                &mut quotient,
            );
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
