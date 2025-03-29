use algebra::random::DiscreteGaussian;
use bigdecimal::BigDecimal;
use num_traits::Zero;
use rand::thread_rng;
use rand_distr::Distribution;

type ValueT = u64;

const Q: ValueT = 1125899906826241;
const STD_DEV: f64 = 0.3908;
const MEAN: f64 = 0.0;

const HALF_Q: ValueT = Q >> 1;
const N: usize = 65536;

fn main() {
    let mut rng = thread_rng();

    let distr = <DiscreteGaussian<ValueT>>::new(MEAN, STD_DEV, Q - 1).unwrap();
    let data: Vec<ValueT> = distr.sample_iter(&mut rng).take(N).collect();

    println!("modulus:{}", Q);
    println!("expect standard deviation:{}", STD_DEV);

    let sum = data.iter().fold(BigDecimal::zero(), |acc, &x| {
        if x <= HALF_Q {
            acc + x
        } else if x < Q {
            acc - (Q - x)
        } else {
            panic!("Err value:{}", x);
        }
    });
    let mean = sum / N as u64;
    let variance = data.iter().fold(BigDecimal::zero(), |acc, &x| {
        let x = if x <= HALF_Q {
            BigDecimal::from(x)
        } else {
            BigDecimal::from(x) - Q
        };
        (x - &mean).square() + acc
    }) / N as u64;

    println!("mean:{}", mean);
    println!("variance:{}", variance);
    println!("standard deviation:{}", variance.sqrt().unwrap());
}
