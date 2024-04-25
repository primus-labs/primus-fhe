use algebra::{
    modulus::{baby_bear::to_monty, *},
    reduce::*,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::prelude::*;
use rand_distr::Uniform;

const BARRETT_U32_P: u32 = 1073707009;
const BARRETT_U64_P: u64 = 1152921504606830593;
const BABY_BEAR_P: u32 = 0x78000001;
const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;

pub fn criterion_benchmark(c: &mut Criterion) {
    let n = 1 << 25;
    let n_for_inv = 1 << 11;

    let mut rng = thread_rng();

    let uniform_barrett = Uniform::new(0, BARRETT_U32_P);

    let barrettmodulus = <BarrettModulus<u32>>::new(BARRETT_U32_P);
    let data1: Vec<u32> = uniform_barrett.sample_iter(&mut rng).take(n).collect();
    let data2: Vec<u32> = uniform_barrett
        .sample_iter(&mut rng)
        .filter(|v| *v != 0)
        .take(n)
        .collect();

    let mut group = c.benchmark_group("u32 barrett modulus");

    group.bench_function(&format!("u32 barrett modulus add {}", n), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.add_reduce(b, barrettmodulus);
                });
        })
    });

    group.bench_function(&format!("u32 barrett modulus sub {}", n), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.sub_reduce(b, barrettmodulus);
                });
        })
    });

    group.bench_function(&format!("u32 barrett modulus mul {}", n), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.mul_reduce(b, barrettmodulus);
                });
        })
    });

    group.bench_function(&format!("u32 barrett modulus neg {}", n), |b| {
        b.iter(|| {
            black_box(&data1).iter().copied().for_each(|a| {
                let _ = a.neg_reduce(barrettmodulus);
            });
        })
    });

    group.bench_function(&format!("u32 barrett modulus reduce {}", n), |b| {
        b.iter(|| {
            black_box(&data1).iter().copied().for_each(|a| {
                let _ = a.reduce(barrettmodulus);
            });
        })
    });

    let data1: Vec<u32> = uniform_barrett
        .sample_iter(&mut rng)
        .take(n_for_inv)
        .collect();
    let data2: Vec<u32> = uniform_barrett
        .sample_iter(&mut rng)
        .filter(|v| *v != 0)
        .take(n_for_inv)
        .collect();

    group.bench_function(&format!("u32 barrett modulus inv {}", n_for_inv), |b| {
        b.iter(|| {
            black_box(&data2).iter().copied().for_each(|a| {
                let _ = a.inv_reduce(barrettmodulus);
            });
        })
    });

    group.bench_function(&format!("u32 barrett modulus div {}", n_for_inv), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.div_reduce(b, barrettmodulus);
                });
        })
    });

    group.finish();

    let uniform_baby_bear = Uniform::new(0, BABY_BEAR_P);

    let data1: Vec<u32> = uniform_baby_bear
        .sample_iter(&mut rng)
        .take(n)
        .map(to_monty)
        .collect();
    let data2: Vec<u32> = uniform_baby_bear
        .sample_iter(&mut rng)
        .take(n)
        .map(to_monty)
        .collect();

    let mut group = c.benchmark_group("baby bear modulus");

    group.bench_function(&format!("baby bear modulus add {}", n), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.add_reduce(b, BabyBearModulus);
                });
        })
    });

    group.bench_function(&format!("baby bear modulus sub {}", n), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.sub_reduce(b, BabyBearModulus);
                });
        })
    });

    group.bench_function(&format!("baby bear modulus mul {}", n), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.mul_reduce(b, BabyBearModulus);
                });
        })
    });

    group.bench_function(&format!("baby bear modulus neg {}", n), |b| {
        b.iter(|| {
            black_box(&data1).iter().copied().for_each(|a| {
                let _ = a.neg_reduce(BabyBearModulus);
            });
        })
    });

    let data1: Vec<u32> = uniform_baby_bear
        .sample_iter(&mut rng)
        .take(n_for_inv)
        .collect();
    let data2: Vec<u32> = uniform_baby_bear
        .sample_iter(&mut rng)
        .filter(|v| *v != 0)
        .take(n_for_inv)
        .collect();

    group.bench_function(&format!("baby bear modulus inv {}", n_for_inv), |b| {
        b.iter(|| {
            black_box(&data2).iter().copied().for_each(|a| {
                let _ = a.inv_reduce(BabyBearModulus);
            });
        })
    });

    group.bench_function(&format!("baby bear modulus div {}", n_for_inv), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.div_reduce(b, BabyBearModulus);
                });
        })
    });

    group.finish();

    let uniform_barrett = Uniform::new(0, BARRETT_U64_P);

    let barrettmodulus = <BarrettModulus<u64>>::new(BARRETT_U64_P);
    let data1: Vec<u64> = uniform_barrett.sample_iter(&mut rng).take(n).collect();
    let data2: Vec<u64> = uniform_barrett
        .sample_iter(&mut rng)
        .filter(|v| *v != 0)
        .take(n)
        .collect();

    let mut group = c.benchmark_group("u64 barrett modulus");

    group.bench_function(&format!("u64 barrett modulus add {}", n), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.add_reduce(b, barrettmodulus);
                });
        })
    });

    group.bench_function(&format!("u64 barrett modulus sub {}", n), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.sub_reduce(b, barrettmodulus);
                });
        })
    });

    group.bench_function(&format!("u64 barrett modulus mul {}", n), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.mul_reduce(b, barrettmodulus);
                });
        })
    });

    group.bench_function(&format!("u64 barrett modulus neg {}", n), |b| {
        b.iter(|| {
            black_box(&data1).iter().copied().for_each(|a| {
                let _ = a.neg_reduce(barrettmodulus);
            });
        })
    });

    group.bench_function(&format!("u64 barrett modulus reduce {}", n), |b| {
        b.iter(|| {
            black_box(&data1).iter().copied().for_each(|a| {
                let _ = a.reduce(barrettmodulus);
            });
        })
    });

    let data1: Vec<u64> = uniform_barrett
        .sample_iter(&mut rng)
        .take(n_for_inv)
        .collect();
    let data2: Vec<u64> = uniform_barrett
        .sample_iter(&mut rng)
        .filter(|v| *v != 0)
        .take(n_for_inv)
        .collect();

    group.bench_function(&format!("u64 barrett modulus inv {}", n_for_inv), |b| {
        b.iter(|| {
            black_box(&data2).iter().copied().for_each(|a| {
                let _ = a.inv_reduce(barrettmodulus);
            });
        })
    });

    group.bench_function(&format!("u64 barrett modulus div {}", n_for_inv), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.div_reduce(b, barrettmodulus);
                });
        })
    });

    group.finish();

    let uniform_goldilocks = Uniform::new(0, GOLDILOCKS_P);

    let mut group = c.benchmark_group("goldilocks modulus");

    let data1: Vec<u64> = uniform_goldilocks.sample_iter(&mut rng).take(n).collect();
    let data2: Vec<u64> = uniform_goldilocks.sample_iter(&mut rng).take(n).collect();

    group.bench_function(&format!("goldilocks modulus add {}", n), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.add_reduce(b, GoldilocksModulus);
                });
        })
    });

    group.bench_function(&format!("goldilocks modulus sub {}", n), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.sub_reduce(b, GoldilocksModulus);
                });
        })
    });

    group.bench_function(&format!("goldilocks modulus mul {}", n), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.mul_reduce(b, GoldilocksModulus);
                });
        })
    });

    group.bench_function(&format!("goldilocks modulus neg {}", n), |b| {
        b.iter(|| {
            black_box(&data1).iter().copied().for_each(|a| {
                let _ = a.neg_reduce(GoldilocksModulus);
            });
        })
    });

    group.bench_function(&format!("goldilocks modulus reduce {}", n), |b| {
        b.iter(|| {
            black_box(&data1).iter().copied().for_each(|a| {
                let _ = a.reduce(GoldilocksModulus);
            });
        })
    });

    let data1: Vec<u64> = uniform_goldilocks
        .sample_iter(&mut rng)
        .take(n_for_inv)
        .collect();
    let data2: Vec<u64> = uniform_goldilocks
        .sample_iter(&mut rng)
        .filter(|v| *v != 0)
        .take(n_for_inv)
        .collect();

    group.bench_function(&format!("goldilocks modulus inv {}", n_for_inv), |b| {
        b.iter(|| {
            black_box(&data2).iter().copied().for_each(|a| {
                let _ = a.inv_reduce(GoldilocksModulus);
            });
        })
    });

    group.bench_function(&format!("goldilocks modulus div {}", n_for_inv), |b| {
        b.iter(|| {
            black_box(&data1)
                .iter()
                .copied()
                .zip(black_box(&data2).iter().copied())
                .for_each(|(a, b)| {
                    let _ = a.div_reduce(b, GoldilocksModulus);
                });
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
