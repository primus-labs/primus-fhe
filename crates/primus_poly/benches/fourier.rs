//! Pointwise Fourier multiplication used by GLWE and NTRU external products.
//! cargo bench -p primus_poly --bench fourier

use std::{hint::black_box, time::Duration};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use num_complex::Complex64;
use primus_poly::FourierPolynomial;

fn fourier(c: &mut Criterion) {
    for n in [512, 1024] {
        let lhs = FourierPolynomial::new(
            (0..n)
                .map(|i| Complex64::new(i as f64 / 13.0, -0.375))
                .collect::<Vec<_>>(),
        );
        let rhs = FourierPolynomial::new(
            (0..n)
                .map(|i| Complex64::new(-0.25, i as f64 / 17.0))
                .collect::<Vec<_>>(),
        );
        let mut output = FourierPolynomial::new(vec![Complex64::default(); n]);
        let mut group = c.benchmark_group(format!("fourier/pointwise/n{n}"));
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function("add_mul", |b| {
            b.iter(|| black_box(&mut output).add_mul_assign(black_box(&lhs), black_box(&rhs)))
        });
        group.bench_function("mul_to", |b| {
            b.iter(|| lhs.mul_to(black_box(&rhs), black_box(&mut output)))
        });
        group.finish();
    }
}
criterion_group! { name = benches; config = Criterion::default().sample_size(20).warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(5)); targets = fourier }
criterion_main!(benches);
