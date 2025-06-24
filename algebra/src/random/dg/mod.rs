use std::{num::NonZero, sync::LazyLock, u128, u64};

use bigdecimal::{BigDecimal, Context, RoundingMode};
use num_traits::{FromPrimitive, One, ToPrimitive, Zero};
use rand_distr::{Distribution, Standard, Uniform};

use crate::{AsInto, UnsignedInteger};

pub use ziggurat::DiscreteZiggurat;

mod ziggurat;

type Float = f64;
const N: usize = 32;
const PRECISION: u64 = 256;

///
#[derive(Debug, Clone, Copy)]
pub struct CumulativeDistributionTableSampler<T: UnsignedInteger> {
    mean: Float,
    std_dev: Float,
    upper_bound: usize,
    modulus_minus_one: T,
    cdt: [u128; N],
}

impl<T: UnsignedInteger> CumulativeDistributionTableSampler<T> {
    ///
    pub fn new(mean: Float, std_dev: Float, modulus_minus_one: T) -> Self {
        let max_std_dev = std_dev * 10.0;
        let mut upper_bound = max_std_dev.ceil() as usize;

        assert!(upper_bound <= N);
        if upper_bound <= 1 {
            upper_bound = 2;
        }

        let context = Context::new(NonZero::new(PRECISION).unwrap(), RoundingMode::HalfUp);

        let std_dev_b = BigDecimal::from_f64(std_dev).unwrap();
        let var_b = std_dev_b.square();

        let minus_twice_variance_recip = -var_b.double().inverse_with_context(&context);

        let mut cdf = vec![BigDecimal::default(); N];
        cdf[0] = BigDecimal::one().half();
        cdf[1] = minus_twice_variance_recip.exp();

        let mut i = 2;
        while i < upper_bound {
            cdf[i] =
                (BigDecimal::from_usize(i).unwrap().square() * &minus_twice_variance_recip).exp();
            i += 1;
        }

        let s = cdf
            .iter()
            .take(upper_bound)
            .fold(BigDecimal::zero(), |acc, v| acc + v);

        let cdf: Vec<BigDecimal> = cdf.into_iter().map(|v| v / &s).take(upper_bound).collect();

        println!("Prob[0]={}", cdf[0]);
        println!("Prob[1]={}", cdf[1]);
        println!("----------------------------------");

        let mut cdt = vec![BigDecimal::default(); N];
        cdt[0] = cdf[0].clone();
        cdt[1] = cdt[0].clone() + &cdf[1];
        let mut i = 2;
        while i < upper_bound {
            cdt[i] = cdt[i - 1].clone() + &cdf[i];
            if cdt[i] >= BigDecimal::one() {
                cdt[i] = BigDecimal::one();
                assert_eq!(upper_bound, i + 1);
                break;
            }
            i += 1;
        }

        let t = BigDecimal::from_u128(u128::MAX).unwrap();

        let new_cdt: Vec<u128> = cdt
            .into_iter()
            .map(|f| {
                (f * &t)
                    .with_scale_round(0, RoundingMode::HalfUp)
                    .to_u128()
                    .unwrap()
            })
            .collect();

        let mut cdt = [0; N];
        for (o, i) in cdt[1..].iter_mut().zip(new_cdt) {
            *o = i;
        }

        Self {
            mean,
            std_dev,
            upper_bound,
            modulus_minus_one,
            cdt,
        }
    }

    /// Returns the mean of this [`CumulativeDistributionTableSampler<T>`].
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Returns the std dev of this [`CumulativeDistributionTableSampler<T>`].
    pub fn std_dev(&self) -> f64 {
        self.std_dev
    }
}

static D: LazyLock<Uniform<u128>> = LazyLock::new(|| Uniform::new_inclusive(0, u128::MAX));

impl<T: UnsignedInteger> Distribution<T> for CumulativeDistributionTableSampler<T> {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let r: u128 = D.sample(rng);

        let mut min = 0;
        let mut cur = self.upper_bound / 2;
        let mut jmp = cur;
        while jmp > 0 {
            cur = min + jmp;
            if r >= unsafe { *self.cdt.get_unchecked(cur) } {
                min = cur;
            }
            jmp >>= 1;
        }

        let v = min.as_into();

        if rng.sample(Standard) {
            v
        } else {
            if v.is_zero() {
                T::ZERO
            } else {
                self.modulus_minus_one - v + T::ONE
            }
        }
    }
}
