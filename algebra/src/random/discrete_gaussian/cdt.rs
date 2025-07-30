use std::{num::NonZero, sync::LazyLock};

use bigdecimal::{BigDecimal, Context, RoundingMode};
use num_traits::{FromPrimitive, One, ToPrimitive, Zero};
use rand_distr::{Distribution, Standard, Uniform};

use crate::{AsInto, UnsignedInteger};

const PRECISION: u64 = 256;

///
#[derive(Debug, Clone)]
pub struct CDTSampler<T: UnsignedInteger> {
    std_dev: f64,
    upper_bound: usize,
    modulus_minus_one: T,
    cdt: Vec<u128>,
}

impl<T: UnsignedInteger> CDTSampler<T> {
    ///
    pub fn new(std_dev: f64, tail_cut: f64, modulus_minus_one: T) -> Self {
        let max_std_dev = std_dev * tail_cut;
        let mut length = max_std_dev.floor() as usize + 1;

        assert!(length <= 1024);
        if length <= 1 {
            length = 2;
        }

        let context = Context::new(NonZero::new(PRECISION).unwrap(), RoundingMode::HalfUp);

        let std_dev_hp = BigDecimal::from_f64(std_dev).unwrap();
        let var_hp = std_dev_hp.square();

        let minus_twice_variance_recip = -var_hp.double().inverse_with_context(&context);

        let mut pdf = vec![BigDecimal::default(); length];
        pdf[0] = BigDecimal::one().half();
        pdf[1] = minus_twice_variance_recip.exp();

        pdf.iter_mut().enumerate().skip(2).for_each(|(i, v)| {
            *v = (BigDecimal::from_usize(i * i).unwrap() * &minus_twice_variance_recip).exp();
        });

        let s = pdf.iter().fold(BigDecimal::zero(), |acc, v| acc + v);

        let pdf: Vec<BigDecimal> = pdf.into_iter().map(|v| v / &s).collect();

        println!("Prob[0]={}", pdf[0]);
        println!("Prob[1]={}", pdf[1]);
        println!("----------------------------------");

        let mut cdt = Vec::with_capacity(length + 1);
        let mut pre = BigDecimal::zero();

        cdt.push(BigDecimal::zero());
        for p in pdf.iter() {
            pre += p;
            if pre < BigDecimal::one() {
                cdt.push(pre.clone());
            } else {
                cdt.push(BigDecimal::one());
                break;
            }
        }
        assert_eq!(cdt.len(), length + 1);

        let cdt: Vec<u128> = cdt
            .into_iter()
            .map(|f| {
                (f * u128::MAX)
                    .with_scale_round(0, RoundingMode::HalfUp)
                    .to_u128()
                    .unwrap()
            })
            .collect();

        Self {
            std_dev,
            upper_bound: length,
            modulus_minus_one,
            cdt,
        }
    }

    /// Returns the std dev of this [`CumulativeDistributionTableSampler<T>`].
    pub fn std_dev(&self) -> f64 {
        self.std_dev
    }
}

static D: LazyLock<Uniform<u128>> = LazyLock::new(|| Uniform::new_inclusive(0, u128::MAX));

impl<T: UnsignedInteger> Distribution<T> for CDTSampler<T> {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let r: u128 = D.sample(rng);

        let mut min = 0;
        let mut max = self.upper_bound;
        while min < max {
            let cur = (min + max) / 2;
            if r < self.cdt[cur] {
                max = cur;
            } else {
                min = cur + 1;
            }
        }
        let idx = min - 1;
        let v = idx.as_into();

        if rng.sample(Standard) {
            v
        } else if v.is_zero() {
            T::ZERO
        } else {
            self.modulus_minus_one - v + T::ONE
        }
    }
}
