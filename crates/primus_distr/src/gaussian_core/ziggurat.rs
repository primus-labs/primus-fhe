use std::f64::consts::{FRAC_1_SQRT_2, FRAC_2_SQRT_PI};

use primus_integer::FheInt;
use rand::{
    RngExt,
    distr::{Bernoulli, Distribution, Uniform},
};

use super::GaussianParameters;
use crate::GaussianError;

const U32_RANGE_END_AS_F64: f64 = 4_294_967_296.0;

#[derive(Clone, Copy)]
enum FallRegion {
    Left,
    Right,
    Middle,
}

/// Discrete Ziggurat implementation shared by signed and modular adapters.
#[derive(Clone)]
pub(crate) struct ZigguratMagnitudeSampler<T: FheInt> {
    standard_deviation: f64,
    inverse_negative_twice_variance: f64,
    x: Vec<f64>,
    y: Vec<f64>,
    y_difference: Vec<f64>,
    slope: Vec<f64>,
    sample_rectangle: Uniform<usize>,
    sample_x: Vec<Uniform<T>>,
    zero_acceptance: Bernoulli,
    strategies: Vec<FallRegion>,
}

impl<T: FheInt> ZigguratMagnitudeSampler<T> {
    /// Construct equal-area proposal layers for the validated, truncated Gaussian support.
    /// Output adapters establish that the support fits T before calling this constructor.
    pub(crate) fn new(parameters: GaussianParameters) -> Result<Self, GaussianError> {
        let standard_deviation = parameters.standard_deviation();
        let maximum_magnitude = parameters.maximum_magnitude() as f64;
        let negative_twice_variance = standard_deviation * standard_deviation * -2.0;

        // For supports above the CDT limit, benchmarks show that 128 layers
        // outperform 64 and 256 in steady-state sampling while retaining much
        // lower setup cost than 256. Smaller direct Ziggurat instances keep
        // leaner initial tables and still fall back by doubling when needed.
        let mut rectangle_count = if maximum_magnitude < 20.0 {
            32
        } else if maximum_magnitude < 100.0 {
            64
        } else {
            128
        };

        'construction: loop {
            let mut x = Vec::with_capacity(rectangle_count + 1);
            let mut y = Vec::with_capacity(rectangle_count + 1);
            x.resize(rectangle_count, 0.0);
            y.resize(rectangle_count, 0.0);
            let initial_area =
                standard_deviation * FRAC_1_SQRT_2 * FRAC_2_SQRT_PI / rectangle_count as f64;

            let mut area_minimum = 0.0;
            let mut area_maximum = maximum_magnitude + 1.0;
            let mut area = initial_area;
            let mut found = false;

            // Rebuild from the tail toward zero while bracketing the common layer area.
            // A layer reaching above the PDF peak too early makes the proposal invalid.
            for iteration in 0..100 {
                let mut previous_y = 0.0;
                let mut previous_x = maximum_magnitude;
                let mut valid = true;

                for (index, (y, x)) in y.iter_mut().rev().zip(x.iter_mut().rev()).enumerate() {
                    *y = area / (1.0 + previous_x) + previous_y;
                    let is_first_rectangle = index == rectangle_count - 1;
                    if !is_first_rectangle && *y >= 1.0 {
                        valid = false;
                        break;
                    }

                    let argument = y.ln() * negative_twice_variance;
                    if argument < 0.0 {
                        if !is_first_rectangle {
                            valid = false;
                            break;
                        }
                        *x = 0.0;
                    } else {
                        *x = argument.sqrt().floor();
                    }

                    previous_y = *y;
                    previous_x = *x;
                }

                if !valid {
                    area_maximum = area;
                    area = (area_minimum + area_maximum) / 2.0;
                    if area_maximum - area_minimum < 1e-10 {
                        break;
                    }
                    continue;
                }

                x[0] = 0.0;
                if y[0] >= 1.0
                    || (y[0] > 0.999 && (area_maximum - area_minimum < 1e-6 || iteration > 20))
                {
                    found = true;
                    break;
                }

                area_minimum = area;
                if area_maximum == maximum_magnitude + 1.0 {
                    area *= 2.0;
                    if area > maximum_magnitude + 1.0 {
                        area_maximum = maximum_magnitude + 1.0;
                        area = (area_minimum + area_maximum) / 2.0;
                    }
                } else {
                    area = (area_minimum + area_maximum) / 2.0;
                }

                if area_maximum - area_minimum < 1e-10 {
                    break;
                }
            }

            if !found {
                rectangle_count *= 2;
                if rectangle_count > 512 {
                    return Err(GaussianError::ZigguratConstructionFailed {
                        standard_deviation,
                        tail_cut: parameters.tail_cut(),
                    });
                }
                continue 'construction;
            }

            x.push(maximum_magnitude);
            y.push(0.0);
            // Zero is shared by both signs. Account for both that duplication
            // and any first-layer height above or below the target PDF at zero.
            let zero_acceptance = Bernoulli::new(0.5 / y[0])
                .expect("a constructed Ziggurat has a valid first-layer height");
            let sample_x = x
                .iter()
                .map(|&value| Uniform::new_inclusive(T::ZERO, T::as_from(value.floor())).unwrap())
                .collect();

            let mut previous_y = y[0];
            let y_difference = y
                .iter()
                .map(|&value| {
                    let difference = previous_y - value;
                    previous_y = value;
                    difference
                })
                .collect();

            let mut previous_x = x[0];
            let mut previous_y = y[0];
            let slope = x
                .iter()
                .zip(&y)
                .enumerate()
                .map(|(index, (&current_x, &current_y))| {
                    let delta_x = current_x - previous_x;
                    previous_x = current_x;
                    if delta_x == 0.0 {
                        previous_y = current_y;
                        return 0.0;
                    }

                    let delta_y = if index == 1 {
                        y[index] - 1.0
                    } else {
                        y[index] - previous_y
                    };
                    previous_y = current_y;
                    delta_y / delta_x
                })
                .collect();

            // Gaussian curvature changes at sigma. A layer wholly on one side
            // can use a chord for early acceptance/rejection; crossing layers use the PDF.
            let mut strategies = Vec::with_capacity(rectangle_count + 1);
            strategies.push(FallRegion::Middle);
            for index in 1..=rectangle_count {
                strategies.push(if x[index] + 1.0 <= standard_deviation {
                    FallRegion::Left
                } else if standard_deviation <= x[index - 1] {
                    FallRegion::Right
                } else {
                    FallRegion::Middle
                });
            }

            return Ok(Self {
                standard_deviation,
                inverse_negative_twice_variance: negative_twice_variance.recip(),
                x,
                y,
                y_difference,
                slope,
                sample_rectangle: Uniform::new_inclusive(1, rectangle_count).unwrap(),
                sample_x,
                zero_acceptance,
                strategies,
            });
        }
    }

    #[inline]
    pub(crate) fn standard_deviation(&self) -> f64 {
        self.standard_deviation
    }

    /// Return an independent sign flag (true means positive) and an accepted magnitude.
    // Sharing magnitude tables between output encodings must not introduce a
    // call per coefficient; sample_secret_key regresses when LLVM outlines it.
    #[inline(always)]
    pub(crate) fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> (bool, T) {
        loop {
            let rectangle = self.sample_rectangle.sample(rng);
            let positive = rng.random();
            let magnitude = self.sample_x[rectangle].sample(rng);
            let magnitude_as_f64 = magnitude.as_into();

            // The inner rectangle is entirely under the PDF; only its fringe needs rejection.
            if magnitude_as_f64 <= self.x[rectangle - 1] && magnitude > T::ZERO {
                return (positive, magnitude);
            }
            if magnitude == T::ZERO {
                if self.zero_acceptance.sample(rng) {
                    return (positive, T::ZERO);
                }
                continue;
            }

            let y = self.y_difference[rectangle] * rng.next_u32() as f64;
            let accepted = match self.strategies[rectangle] {
                FallRegion::Left => {
                    y <= U32_RANGE_END_AS_F64 * self.line(rectangle, magnitude_as_f64)
                        || y <= U32_RANGE_END_AS_F64
                            * (self.pdf(magnitude_as_f64) - self.y[rectangle])
                }
                FallRegion::Right => {
                    !(y >= U32_RANGE_END_AS_F64 * self.line(rectangle, magnitude_as_f64 - 1.0)
                        || y > U32_RANGE_END_AS_F64
                            * (self.pdf(magnitude_as_f64) - self.y[rectangle]))
                }
                FallRegion::Middle => {
                    y <= U32_RANGE_END_AS_F64 * (self.pdf(magnitude_as_f64) - self.y[rectangle])
                }
            };

            if accepted {
                return (positive, magnitude);
            }
        }
    }

    /// Chord height relative to the layer base; a collapsed interval uses a negative sentinel instead of a chord.
    #[inline(always)]
    fn line(&self, index: usize, x: f64) -> f64 {
        if self.x[index] == self.x[index - 1] {
            -1.0
        } else {
            self.slope[index] * (x - self.x[index])
        }
    }

    #[inline(always)]
    fn pdf(&self, x: f64) -> f64 {
        (x * x * self.inverse_negative_twice_variance).exp()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This sigma produces a first layer above the peak; zero still needs exactly half mass.
    #[test]
    fn zero_acceptance_compensates_first_layer_height() {
        let parameters = GaussianParameters::new(53.065, 12.0).unwrap();
        let sampler = ZigguratMagnitudeSampler::<u64>::new(parameters).unwrap();

        let corrected_zero_mass = sampler.zero_acceptance.p() * sampler.y[0];
        assert!((corrected_zero_mass - 0.5).abs() < 1e-15);
    }
}
