use std::f64::consts::{FRAC_1_SQRT_2, FRAC_2_SQRT_PI};

use rand_distr::{Distribution, Standard, Uniform};

use crate::UnsignedInteger;

///
#[derive(Clone)]
pub struct DiscreteZiggurat<T: UnsignedInteger> {
    sigma: f64,
    x: Vec<f64>,
    y: Vec<f64>,
    sample_m: Uniform<usize>,
    sample_x: Vec<Uniform<T>>,
    modulus_minus_one: T,
}

impl<T: UnsignedInteger> DiscreteZiggurat<T> {
    ///
    pub fn new(sigma: f64, t: f64, modulus_minus_one: T) -> Self {
        let x_m = (t * sigma).floor();
        let sigma_square_mul_minus_two = sigma * sigma * (-2.0f64);

        let mut m = 7;
        'outer: loop {
            let mut x = Vec::with_capacity(m + 1);
            let mut y = Vec::with_capacity(m + 1);

            x.resize(m, 0.0);
            y.resize(m, 0.0);

            let initial_s = sigma * FRAC_1_SQRT_2 * FRAC_2_SQRT_PI / (m as f64);

            let mut s = initial_s;
            loop {
                let mut pre_y = 0f64;
                let mut pre_x = x_m;
                for (y, x) in y.iter_mut().rev().zip(x.iter_mut().rev()) {
                    *y = s / (1.0f64 + pre_x) + pre_y;
                    *x = ((*y).ln() * sigma_square_mul_minus_two).sqrt().floor();
                    pre_y = *y;
                    pre_x = *x;
                }
                x[0] = 0f64;
                if y[0] > 1.0 {
                    break;
                }
                s += initial_s;
                if s > x_m + 1.0 {
                    m += 1;
                    if m == 258 {
                        panic!("error");
                    }
                    continue 'outer;
                }
            }
            x.push(x_m);
            y.push(0.0);
            let sample_x: Vec<Uniform<T>> = x
                .iter()
                .map(|&v| Uniform::new_inclusive(T::ZERO, T::as_from(v.floor())))
                .collect();
            break Self {
                sigma,
                x,
                y,
                sample_m: Uniform::new_inclusive(1, m),
                sample_x,
                modulus_minus_one,
            };
        }
    }
}

impl<T: UnsignedInteger> Distribution<T> for DiscreteZiggurat<T> {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let pdf = |x: f64| ((x * x) / (-2.0 * self.sigma * self.sigma)).exp();
        let combine = |sign: bool, x: T| {
            if sign {
                x
            } else {
                self.modulus_minus_one - x + T::ONE
            }
        };

        loop {
            let i = self.sample_m.sample(rng);
            let sign: bool = Standard.sample(rng);
            let x = self.sample_x[i].sample(rng);

            let x_f: f64 = x.as_into();

            if x_f <= self.x[i - 1] && x > T::ZERO {
                return combine(sign, x);
            } else {
                if x == T::ZERO {
                    if Standard.sample(rng) {
                        return T::ZERO;
                    } else {
                        continue;
                    }
                } else {
                    let mask = 2.0f64.powi(32);
                    let y_prime = rng.next_u32();
                    let y = (self.y[i - 1] - self.y[i]) * y_prime as f64;

                    if self.x[i] + 1.0 <= self.sigma {
                        if y <= mask
                            * s_line(i, self.x[i - 1], self.x[i], self.y[i - 1], self.y[i], x_f)
                            || y <= mask * (pdf(x_f) - self.y[i])
                        {
                            return combine(sign, x);
                        } else {
                            continue;
                        }
                    } else if self.sigma <= self.x[i - 1] {
                        if y >= mask
                            * s_line(
                                i,
                                self.x[i - 1],
                                self.x[i],
                                self.y[i - 1],
                                self.y[i],
                                x_f - 1.0,
                            )
                            || y > mask * (pdf(x_f) - self.y[i])
                        {
                            continue;
                        } else {
                            return combine(sign, x);
                        }
                    } else {
                        if y <= mask * (pdf(x_f) - self.y[i]) {
                            return combine(sign, x);
                        } else {
                            continue;
                        }
                    }
                }
            }
        }
    }
}

fn s_line(i: usize, x_i_minus_one: f64, x_i: f64, y_i_minus_one: f64, y_i: f64, x: f64) -> f64 {
    if x_i == x_i_minus_one {
        return -1.0;
    }
    if i == 1 {
        (y_i - 1.0) * (x - x_i) / (x_i - x_i_minus_one)
    } else {
        (y_i - y_i_minus_one) * (x - x_i) / (x_i - x_i_minus_one)
    }
}
