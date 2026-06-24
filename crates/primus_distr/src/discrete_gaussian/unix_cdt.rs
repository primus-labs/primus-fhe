use primus_integer::{AsInto, FheUint};
use rand::distr::Distribution;
use rug::{Float, az::Cast};

const PRECISION: u32 = 512;

/// High-precision CDT sampler using 256-bit arithmetic (Unix only).
///
/// Uses the `rug` crate for arbitrary-precision floating-point computation
/// and stores entries as `[u64; 4]` for 256-bit comparison during sampling.
#[derive(Debug, Clone)]
pub struct UnixCDTSampler<T: FheUint> {
    std_dev: f64,
    modulus_minus_one: T,
    cdt: Vec<[u64; 4]>,
}

impl<T: FheUint> UnixCDTSampler<T> {
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

        let mut pre = minus_twice_variance_recip.clone().exp();
        pdf[1] = pre.clone();
        for i in 2..length {
            let factor = Float::with_val(PRECISION, 2 * i - 1) * &minus_twice_variance_recip;
            pre = pre * factor.exp();
            pdf[i] = pre.clone();
        }

        let s = pdf.iter().fold(Float::new(PRECISION), |acc, v| acc + v);

        let mut cdt = Vec::with_capacity(length + 1);
        let mut acc = Float::new(PRECISION);

        cdt.push(Float::new(PRECISION));
        for p in pdf.iter() {
            acc += p;
            if acc < s {
                cdt.push(Float::with_val(PRECISION, &acc / &s));
            } else {
                cdt.push(Float::with_val(PRECISION, 1));
                break;
            }
        }
        assert_eq!(cdt.len(), length + 1);

        let scalar = rug::Integer::from(1) << 256;
        let cdt: Vec<[u64; 4]> = cdt
            .into_iter()
            .map(|f| {
                if f == 1 {
                    [u64::MAX; 4]
                } else {
                    let t: Float = f * &scalar;
                    let temp: rug::Integer = t.cast();
                    let digits: Vec<u64> = temp.to_digits(rug::integer::Order::Lsf);

                    debug_assert!(
                        digits.len() <= 4,
                        "CDT value exceeds 256 bits: got {} u64 digits",
                        digits.len()
                    );

                    let mut result = [0u64; 4];
                    let len = digits.len().min(4);
                    result[..len].copy_from_slice(&digits[..len]);
                    result
                }
            })
            .collect();

        Self {
            std_dev,
            modulus_minus_one,
            cdt,
        }
    }

    /// Returns the standard deviation of this [`UnixCDTSampler<T>`].
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.std_dev
    }
}

impl<T: FheUint> Distribution<T> for UnixCDTSampler<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let mut r = [0u64; 4];
        rng.fill(&mut r);
        let positive = (r[0] & 1) == 1;

        let idx = self.cdt.partition_point(|x| cmp_u256(x, &r).is_le()) - 1;
        let v: T = idx.as_into();

        if v.is_zero() {
            return T::ZERO;
        }

        if positive {
            v
        } else {
            self.modulus_minus_one - v + T::ONE
        }
    }
}

#[inline(always)]
fn cmp_u256(a: &[u64; 4], b: &[u64; 4]) -> std::cmp::Ordering {
    for i in (0..4).rev() {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}
