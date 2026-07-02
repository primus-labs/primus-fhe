use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_modulus::BarrettModulus;
use primus_ntt::{Concrete64Table, HexlNttTable, NttTable, UintNttTable};
use rand::distr::{Distribution, Uniform};

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = rand::rng();
    for q in [536813569u64, 562949953392641u64, 1152921504606830593u64] {
        for n in [512usize, 1024, 2048, 4096] {
            if q % (2 * n as u64) != 1 {
                continue;
            }

            let modulus = BarrettModulus::new(q);
            let distr = Uniform::new(0, q).unwrap();
            let log_n: u32 = n.trailing_zeros();

            let hexl_table = HexlNttTable::new(log_n, modulus).unwrap();
            let uint_table = UintNttTable::new(log_n, modulus).unwrap();
            let concrete_table = Concrete64Table::new(log_n, modulus).unwrap();

            let mut poly1: Vec<u64> = distr.sample_iter(&mut rng).take(n).collect();
            let mut poly2: Vec<u64> = poly1.clone();
            let mut poly3: Vec<u64> = poly1.clone();

            c.bench_function(&format!("Hexl NTT: q:{q} n:{n}"), |b| {
                b.iter(|| {
                    hexl_table.transform_slice(black_box(&mut poly1));
                })
            });

            c.bench_function(&format!("Uint NTT: q:{q} n:{n}"), |b| {
                b.iter(|| {
                    uint_table.transform_slice(black_box(&mut poly2));
                })
            });

            c.bench_function(&format!("Concrete NTT: q:{q} n:{n}"), |b| {
                b.iter(|| {
                    concrete_table.transform_slice(black_box(&mut poly3));
                })
            });

            poly1
                .iter_mut()
                .zip(distr.sample_iter(&mut rng))
                .for_each(|(a, b)| *a = b);
            poly2.clone_from_slice(&poly1);
            poly3.clone_from_slice(&poly1);

            c.bench_function(&format!("Hexl INTT: q:{q} n:{n}"), |b| {
                b.iter(|| {
                    hexl_table.inverse_transform_slice(black_box(&mut poly1));
                })
            });

            c.bench_function(&format!("Uint INTT: q:{q} n:{n}"), |b| {
                b.iter(|| {
                    uint_table.inverse_transform_slice(black_box(&mut poly2));
                })
            });

            c.bench_function(&format!("Concrete INTT: q:{q} n:{n}"), |b| {
                b.iter(|| {
                    concrete_table.inverse_transform_slice(black_box(&mut poly3));
                })
            });
        }
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
