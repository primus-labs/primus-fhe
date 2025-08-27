// cargo r -r -p algebra --example gaussian

use bigdecimal::BigDecimal;
use num_traits::{ConstZero, Zero};
use rand::thread_rng;
use rand_distr::Distribution;
use serde::{Deserialize, Serialize};

type ValueT = u64;

const Q: ValueT = 1125899906826241;
const HALF_Q: ValueT = Q >> 1;
const N: usize = 1 << 20;

fn main() {
    check_standard_deviation();
    // get_ration();
}

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    x: f64,
    y: f64,
}

// fn get_ration() {
// use num_traits::{FromPrimitive, ToPrimitive};
//     let mut rng = thread_rng();
//     let mut wtr = csv::Writer::from_path("d2c.csv").unwrap();

//     let sigams: Vec<f64> = (100..1000)
//         .into_iter()
//         .map(|v| v as f64 / 1000.0f64)
//         .collect();
//     let mut data: Vec<ValueT> = vec![ValueT::ZERO; N];

//     for continuous_sigma in sigams {
//         let distr = <DiscreteGaussian<ValueT>>::new(MEAN, continuous_sigma, Q - 1).unwrap();
//         data.iter_mut()
//             .zip(distr.sample_iter(&mut rng))
//             .for_each(|(d, v)| *d = v);

//         let sum = data.iter().fold(BigDecimal::zero(), |acc, &x| {
//             if x <= HALF_Q {
//                 acc + x
//             } else if x < Q {
//                 acc - (Q - x)
//             } else {
//                 panic!("Err value:{}", x);
//             }
//         });
//         let mean = sum / N as u64;
//         let variance = data.iter().fold(BigDecimal::zero(), |acc, &x| {
//             let x = if x <= HALF_Q {
//                 BigDecimal::from(x)
//             } else {
//                 BigDecimal::from(x) - Q
//             };
//             (x - &mean).square() + acc
//         }) / N as u64;

//         let discrete_sigma = variance.sqrt().unwrap();

//         let x: BigDecimal = discrete_sigma.with_scale_round(5, bigdecimal::RoundingMode::HalfUp);
//         let ratio: BigDecimal =
//             (variance - BigDecimal::from_f64(continuous_sigma).unwrap().square()) * 12;
//         let y: BigDecimal = ratio.with_scale_round(5, bigdecimal::RoundingMode::HalfUp);

//         wtr.serialize(Record {
//             x: x.to_f64().unwrap(),
//             y: y.to_f64().unwrap(),
//         })
//         .unwrap();
//     }
//     wtr.flush().unwrap();
// }

fn check_standard_deviation() {
    let mut rng = thread_rng();

    // let sigams: Vec<f64> = (1..10).into_iter().map(|v| v as f64 / 10.0f64).collect();
    // let sigams: Vec<f64> = vec![1024f64, 4096f64, 8192f64, 16384f64, 32768f64, 65536f64];
    let sigams: Vec<f64> = vec![0.5];

    let chunk_size = 10usize;
    let modulus = <algebra::modulus::BarrettModulus<ValueT>>::new(Q);

    let mut data: Vec<ValueT> = vec![ValueT::ZERO; N];
    for sigma in sigams {
        println!("----------------single-------------------------");
        let distr = <algebra::random::CDTSampler<ValueT>>::new(sigma, 9.42, Q - 1);
        // let distr = <algebra::random::DiscreteZiggurat<ValueT>>::new(sigma, 9.42, Q - 1);
        // let distr = <algebra::random::DiscreteGaussian<ValueT>>::new(0.0, sigma, Q - 1).unwrap();
        // let distr = <algebra::random::UnixCDTSampler<ValueT>>::new(sigma, 9.42, Q - 1);
        data.iter_mut()
            .zip(distr.clone().sample_iter(&mut rng))
            .for_each(|(d, v)| *d = v);

        check(&data, sigma);

        let datas: Vec<Vec<ValueT>> = (0..chunk_size)
            .map(|_| distr.clone().sample_iter(&mut rng).take(N).collect())
            .collect();

        let new_data = datas
            .into_iter()
            .reduce(|mut acc, x| {
                for (a, b) in acc.iter_mut().zip(x) {
                    algebra::reduce::ReduceAddAssign::reduce_add_assign(modulus, a, b);
                }
                acc
            })
            .unwrap();

        println!("----------------sum-------------------------");

        check(&new_data, (chunk_size as f64).sqrt() * sigma);
    }
}

fn check(data: &[ValueT], sigma: f64) {
    println!("expect standard deviation:{}", sigma);

    let one_sigma = sigma.trunc() as ValueT;
    let two_sigma = (sigma * 2.0).trunc() as ValueT;
    let three_sigma = (sigma * 3.0).trunc() as ValueT;
    let four_sigma = (sigma * 4.0).trunc() as ValueT;
    let five_sigma = (sigma * 5.0).trunc() as ValueT;
    let six_sigma = (sigma * 6.0).trunc() as ValueT;
    let mut one_sigma_count = 0usize;
    let mut two_sigma_count = 0usize;
    let mut three_sigma_count = 0usize;
    let mut four_sigma_count = 0usize;
    let mut five_sigma_count = 0usize;
    let mut six_sigma_count = 0usize;

    let sum = data.iter().fold(BigDecimal::zero(), |acc, &x| {
        if x <= HALF_Q {
            if x <= six_sigma {
                six_sigma_count += 1;
                if x <= five_sigma {
                    five_sigma_count += 1;
                    if x <= four_sigma {
                        four_sigma_count += 1;
                        if x <= three_sigma {
                            three_sigma_count += 1;
                            if x <= two_sigma {
                                two_sigma_count += 1;
                                if x <= one_sigma {
                                    one_sigma_count += 1;
                                }
                            }
                        }
                    }
                }
            }
            acc + x
        } else if x < Q {
            let t = Q - x;
            if t <= six_sigma {
                six_sigma_count += 1;
                if t <= five_sigma {
                    five_sigma_count += 1;
                    if t <= four_sigma {
                        four_sigma_count += 1;
                        if t <= three_sigma {
                            three_sigma_count += 1;
                            if t <= two_sigma {
                                two_sigma_count += 1;
                                if t <= one_sigma {
                                    one_sigma_count += 1;
                                }
                            }
                        }
                    }
                }
            }
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

    println!("real standard deviation:{}", variance.sqrt().unwrap());
    println!("real mean:{}", mean);
    println!("----------------------------------");
    println!("one sigma count:{}", one_sigma_count);
    println!("two sigma count:{}", two_sigma_count);
    println!("three sigma count:{}", three_sigma_count);
    println!("four sigma count:{}", four_sigma_count);
    println!("five sigma count:{}", five_sigma_count);
    println!("six sigma count:{}", six_sigma_count);
    println!("----------------------------------");
    println!("one sigma ratio:{}", one_sigma_count as f64 / N as f64);
    println!("two sigma ratio:{}", two_sigma_count as f64 / N as f64);
    println!("three sigma ratio:{}", three_sigma_count as f64 / N as f64);
    println!("four sigma ratio:{}", four_sigma_count as f64 / N as f64);
    println!("five sigma ratio:{}", five_sigma_count as f64 / N as f64);
    println!("six sigma ratio:{}", six_sigma_count as f64 / N as f64);
    println!(
        "more than six sigma ratio:{}",
        1.0 - six_sigma_count as f64 / N as f64
    );
    println!("----------------------------------");
    // println!(
    //     "Prob[0]={}",
    //     data.iter().filter(|v| **v == 0).count() as f64 / N as f64
    // );
    // println!(
    //     "Prob[1]={}",
    //     data.iter().filter(|v| **v == 1 || **v == Q - 1).count() as f64 / N as f64
    // );
    let mut count: Vec<usize> = vec![0; 16];
    data.iter()
        .filter(|i| **i < 16)
        .for_each(|i| count[*i as usize] += 1);

    for (i, c) in count.into_iter().take(10).enumerate() {
        println!("Prob[{}]={}", { i }, c as f64 / N as f64);
    }

    println!("----------------------------------\n\n");
}
