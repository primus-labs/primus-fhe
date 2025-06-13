use std::{f64::consts::TAU, u64};

use rand_distr::{Distribution, Standard};

use crate::{AsInto, UnsignedInteger};

type Float = f64;
const N: usize = 32;

///
#[derive(Debug, Clone, Copy)]
pub struct CumulativeDistributionTableSampler<T: UnsignedInteger> {
    mean: Float,
    std_dev: Float,
    upper_bound: usize,
    modulus_minus_one: T,
    cdt: [u64; N],
}

impl<T: UnsignedInteger> CumulativeDistributionTableSampler<T> {
    ///
    pub fn new(mean: Float, std_dev: Float, modulus_minus_one: T) -> Self {
        let max_std_dev = std_dev * 10.0;
        let mut upper_bound = max_std_dev.floor() as usize;

        assert!(upper_bound < N);
        upper_bound = upper_bound.next_power_of_two();

        let s = (TAU.sqrt() * std_dev).recip();
        let s2 = s * 2.0;

        let mut cdf = [0.0; N];
        cdf[0] = 0.5 * s;
        println!("Prob[0]={}", cdf[0]);
        cdf[1] = (-(std_dev * std_dev * 2.0).recip()).exp() * s2;
        println!("Prob[1]={}", cdf[1]);

        let mut i = 2;
        while i <= upper_bound {
            let i_f = i as Float;
            let i_f_square = i_f * i_f;
            cdf[i] = (-(std_dev * std_dev * 2.0).recip() * i_f_square).exp() * s2;
            i += 1;
        }
        println!("Prob[2]={}", cdf[2]);

        let mut cdt = [0.0; N];
        cdt[0] = 0.5;
        cdt[1] = 0.5 + cdf[1];
        let mut i = 2;
        while i <= upper_bound {
            cdt[i] = cdt[i - 1] + cdf[i];
            assert!(cdt[i] <= 1.0);
            i += 1;
        }

        let new_cdt = cdt
            // .map(|f| ((HALF as f64) * f) as u64 + ((HALF as f64) * (f * 2.0f64.powi(32))) as u64);
            .map(|f| (2.0f64.powi(64) * f) as u64);

        Self {
            mean,
            std_dev,
            upper_bound,
            modulus_minus_one,
            cdt: new_cdt,
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

impl<T: UnsignedInteger> Distribution<T> for CumulativeDistributionTableSampler<T> {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let r = rng.next_u64();

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
