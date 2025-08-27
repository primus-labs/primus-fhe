use rand_distr::{Distribution, Standard};
use rug::{az::Cast, Float};

use crate::{AsInto, UnsignedInteger};

const PRECISION: u32 = 512;

/// UnixCDTSampler
#[derive(Debug, Clone)]
pub struct UnixCDTSampler<T: UnsignedInteger> {
    std_dev: f64,
    upper_bound: usize,
    modulus_minus_one: T,
    cdt: Vec<rug::Integer>,
}

impl<T: UnsignedInteger> UnixCDTSampler<T> {
    /// Generate UnixCDTSampler
    pub fn new(std_dev: f64, tail_cut: f64, modulus_minus_one: T) -> Self {
        let mut length = (std_dev * tail_cut).floor() as usize + 1;

        assert!(length <= 1024);
        if length <= 1 {
            length = 2;
        }

        let std_dev_hp = Float::with_val(PRECISION, std_dev);
        let var_hp = std_dev_hp.square();

        let minus_twice_variance_recip = -(var_hp * 2u32).recip();

        let mut pdf = vec![Float::new(PRECISION); length];
        pdf[0] = Float::with_val(PRECISION, 1) / 2;
        pdf[1] = minus_twice_variance_recip.clone().exp();

        pdf.iter_mut().enumerate().skip(2).for_each(|(i, v)| {
            *v = (Float::with_val(PRECISION, i * i) * &minus_twice_variance_recip).exp();
        });

        let s = pdf.iter().fold(Float::new(PRECISION), |acc, v| acc + v);

        let pdf: Vec<Float> = pdf.into_iter().map(|v| v / &s).collect();

        let mut cdt = Vec::with_capacity(length + 1);
        let mut pre = Float::new(PRECISION);

        cdt.push(Float::new(PRECISION));
        for p in pdf.iter() {
            pre += p;
            if pre < Float::with_val(PRECISION, 1) {
                cdt.push(pre.clone());
            } else {
                cdt.push(Float::with_val(PRECISION, 1));
                break;
            }
        }
        assert_eq!(cdt.len(), length + 1);

        let scalar = rug::Integer::from(1) << 256;
        let cdt: Vec<rug::Integer> = cdt
            .into_iter()
            .map(|f| {
                let t: Float = f * &scalar;
                t.cast()
            })
            .collect();

        Self {
            std_dev,
            upper_bound: length,
            modulus_minus_one,
            cdt,
        }
    }

    /// Returns the std dev of this [`UnixCDTSampler<T>`].
    pub fn std_dev(&self) -> f64 {
        self.std_dev
    }
}

impl<T: UnsignedInteger> Distribution<T> for UnixCDTSampler<T> {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let r: [u32; 8] = Standard.sample(rng);
        let r = rug::Integer::from_digits(&r, rug::integer::Order::Lsf);

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
