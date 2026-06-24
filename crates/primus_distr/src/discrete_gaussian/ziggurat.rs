use std::f64::consts::{FRAC_1_SQRT_2, FRAC_2_SQRT_PI};

use primus_integer::FheUint;
use rand::{
    RngExt,
    distr::{Distribution, Uniform},
};

#[derive(Clone, Copy)]
enum FallRegion {
    Left,   // x[i] + 1.0 <= std_dev
    Right,  // std_dev <= x[i-1]
    Middle, // Other case
}

/// Discrete Ziggurat
#[derive(Clone)]
pub struct DiscreteZiggurat<T: FheUint> {
    std_dev: f64,
    inv_neg_two_std_dev_sq: f64,
    x: Vec<f64>,
    y: Vec<f64>,
    y_diff: Vec<f64>, // Precomputed y[i-1] - y[i]
    slope: Vec<f64>,  // Precomputed (y[i] - y[i-1]) / (x[i] - x[i-1])
    sample_m: Uniform<usize>,
    sample_x: Vec<Uniform<T>>,
    strategies: Vec<FallRegion>,
    modulus_minus_one: T,
}

impl<T: FheUint> DiscreteZiggurat<T> {
    /// Generate a [`DiscreteZiggurat<T>`]
    pub fn new(std_dev: f64, tail_cut: f64, modulus_minus_one: T) -> Self {
        let x_m = (tail_cut * std_dev).floor();
        let neg_two_std_dev_sq = std_dev * std_dev * (-2.0f64);

        let mut m = if x_m < 20.0 {
            32
        } else if x_m < 100.0 {
            64
        } else {
            128
        };

        'outer: loop {
            let mut x = Vec::with_capacity(m + 1);
            let mut y = Vec::with_capacity(m + 1);

            x.resize(m, 0.0);
            y.resize(m, 0.0);

            let initial_s = std_dev * FRAC_1_SQRT_2 * FRAC_2_SQRT_PI / (m as f64);

            // Use binary search to find the right s value
            let mut s_min = 0.0;
            let mut s_max = x_m + 1.0;
            let mut s = initial_s;
            let mut found = false;

            // Try at most 100 iterations to find a valid s
            for _iteration in 0..100 {
                let mut pre_y = 0f64;
                let mut pre_x = x_m;
                let mut valid = true;

                for (idx, (y, x)) in y.iter_mut().rev().zip(x.iter_mut().rev()).enumerate() {
                    *y = s / (1.0f64 + pre_x) + pre_y;

                    // For all y values except y[0], enforce strict y < 1.0
                    // For y[0], we allow it to reach or slightly exceed 1.0 since it should equal pdf(0) = 1.0
                    let is_y0 = idx == m - 1;
                    if !is_y0 && *y >= 1.0 {
                        // s is too large for intermediate values
                        valid = false;
                        break;
                    }

                    let arg = (*y).ln() * neg_two_std_dev_sq;
                    if arg < 0.0 {
                        // ln(y) * neg_two_std_dev_sq < 0 means y > 1.0 (since neg_two_std_dev_sq < 0)
                        // This should only happen for y[0] in edge cases
                        if !is_y0 {
                            valid = false;
                            break;
                        }
                        // For y[0] >= 1.0, set x[0] to 0 (will be overwritten below anyway)
                        *x = 0.0;
                    } else {
                        *x = arg.sqrt().floor();
                    }

                    pre_y = *y;
                    pre_x = *x;
                }

                if !valid {
                    // s is too large
                    s_max = s;
                    s = (s_min + s_max) / 2.0;
                    if s_max - s_min < 1e-10 {
                        // Cannot find valid s, need more rectangles
                        break;
                    }
                    continue;
                }

                x[0] = 0f64;

                // Accept if y[0] >= 1.0 (ideal case) or very close to 1.0
                // y[0] should equal pdf(0) = 1.0 for proper coverage of the distribution
                if y[0] >= 1.0 {
                    // Ideal case: found s such that y[0] >= 1.0 and all intermediate y < 1.0
                    found = true;
                    break;
                } else if y[0] > 0.999 && (s_max - s_min < 1e-6 || _iteration > 20) {
                    // Accept if very close to 1.0 and either:
                    // - Search range is very narrow (binary search has converged)
                    // - We've done many iterations (avoid infinite search)
                    found = true;
                    break;
                } else {
                    // s is too small, need to increase it
                    s_min = s;
                    if s_max == x_m + 1.0 {
                        // Haven't found upper bound yet, try doubling
                        s *= 2.0;
                        if s > x_m + 1.0 {
                            s_max = x_m + 1.0;
                            s = (s_min + s_max) / 2.0;
                        }
                    } else {
                        // Binary search
                        s = (s_min + s_max) / 2.0;
                    }

                    if s_max - s_min < 1e-10 {
                        // Cannot find valid s, need more rectangles
                        break;
                    }
                }
            }

            if !found {
                // Need more rectangles
                m *= 2;
                if m > 512 {
                    panic!(
                        "Cannot construct Ziggurat with m > 512 for std_dev={}, tail_cut={}",
                        std_dev, tail_cut
                    );
                }
                continue 'outer;
            }

            x.push(x_m);
            y.push(0.0);
            let sample_x: Vec<Uniform<T>> = x
                .iter()
                .map(|&v| Uniform::new_inclusive(T::ZERO, T::as_from(v.floor())).unwrap())
                .collect();

            // Precompute y_diff: y[i-1] - y[i] for i in 1..=m
            let mut pre = y[0];
            let y_diff: Vec<f64> = y
                .iter()
                .map(|&v| {
                    let temp = pre - v;
                    pre = v;
                    temp
                })
                .collect();

            // Precompute slope: (y[i] - y[i-1]) / (x[i] - x[i-1]) for i in 1..=m
            let mut pre_x = x[0];
            let mut pre_y = y[0];
            let slope = x
                .iter()
                .zip(y.iter())
                .enumerate()
                .map(|(i, (&x_i, &y_i))| {
                    let dx = x_i - pre_x;
                    pre_x = x_i;
                    if dx != 0.0 {
                        let dy = if i == 1 {
                            y[i] - 1.0 // Special case for i=1
                        } else {
                            y[i] - pre_y
                        };
                        pre_y = y_i;
                        dy / dx
                    } else {
                        pre_y = y_i;
                        0.0
                    }
                })
                .collect();

            let mut strategies = Vec::with_capacity(m + 1);
            strategies.push(FallRegion::Middle);

            for i in 1..=m {
                let strategy = if x[i] + 1.0 <= std_dev {
                    FallRegion::Left
                } else if std_dev <= x[i - 1] {
                    FallRegion::Right
                } else {
                    FallRegion::Middle
                };
                strategies.push(strategy);
            }

            break Self {
                std_dev,
                inv_neg_two_std_dev_sq: neg_two_std_dev_sq.recip(),
                x,
                y,
                y_diff,
                slope,
                sample_m: Uniform::new_inclusive(1, m).unwrap(),
                sample_x,
                strategies,
                modulus_minus_one,
            };
        }
    }

    /// Returns the std dev of this [`DiscreteZiggurat<T>`].
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.std_dev
    }

    /// Compute the line segment value using precomputed slope
    #[inline(always)]
    fn s_line(&self, i: usize, x: f64) -> f64 {
        if self.x[i] == self.x[i - 1] {
            return -1.0;
        }
        self.slope[i] * (x - self.x[i])
    }

    #[inline(always)]
    fn pdf(&self, x: f64) -> f64 {
        // ((x * x) / self.neg_two_std_dev_sq).exp()
        (x * x * self.inv_neg_two_std_dev_sq).exp()
    }

    #[inline(always)]
    fn combine(&self, sign: bool, x: T) -> T {
        if sign {
            x
        } else {
            self.modulus_minus_one - x + T::ONE
        }
    }
}

const MASK: f64 = 4294967296.0f64; // 2^{32}

impl<T: FheUint> Distribution<T> for DiscreteZiggurat<T> {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        loop {
            let i = self.sample_m.sample(rng);
            let sign: bool = rng.random();
            let x = self.sample_x[i].sample(rng);

            let x_f: f64 = x.as_into();

            if x_f <= self.x[i - 1] && x > T::ZERO {
                return self.combine(sign, x);
            } else if x == T::ZERO {
                if rng.random() {
                    return T::ZERO;
                } else {
                    continue;
                }
            } else {
                let y_prime = rng.next_u32();
                let y = self.y_diff[i] * y_prime as f64;

                match self.strategies[i] {
                    FallRegion::Left => {
                        if y <= MASK * self.s_line(i, x_f)
                            || y <= MASK * (self.pdf(x_f) - self.y[i])
                        {
                            return self.combine(sign, x);
                        } else {
                            continue;
                        }
                    }
                    FallRegion::Right => {
                        if y >= MASK * self.s_line(i, x_f - 1.0)
                            || y > MASK * (self.pdf(x_f) - self.y[i])
                        {
                            continue;
                        } else {
                            return self.combine(sign, x);
                        }
                    }
                    FallRegion::Middle => {
                        if y <= MASK * (self.pdf(x_f) - self.y[i]) {
                            return self.combine(sign, x);
                        } else {
                            continue;
                        }
                    }
                }
            }
        }
    }
}
