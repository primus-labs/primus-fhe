use super::GaussianParameters;

/// Builds the portable CDT shared by signed and modular output adapters.
#[inline]
pub(crate) fn build_cdt(parameters: GaussianParameters) -> (f64, Vec<u64>) {
    let standard_deviation = parameters.standard_deviation();
    let length = parameters.maximum_magnitude() as usize + 1;
    let two_variance = 2.0 * standard_deviation * standard_deviation;

    let mut log_pdf = vec![f64::NEG_INFINITY; length];
    // A separate random sign doubles every nonzero magnitude, so zero needs half weight.
    log_pdf[0] = 0.5f64.ln();
    for (magnitude, log_probability) in log_pdf.iter_mut().enumerate().skip(1) {
        let magnitude = magnitude as f64;
        *log_probability = -(magnitude * magnitude) / two_variance;
    }

    // Normalize in log space before summation to keep the retained mass numerically usable.
    let max_log_probability = log_pdf.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    for log_probability in &mut log_pdf {
        *log_probability = (*log_probability - max_log_probability).exp();
    }
    let probability_sum: f64 = log_pdf.iter().sum();

    let mut cdt = vec![0; length + 1];
    let mut cumulative_probability = 0.0;

    for (&probability, bound) in log_pdf.iter().zip(&mut cdt[1..]) {
        cumulative_probability += probability;
        let normalized_cumulative_probability = (cumulative_probability / probability_sum).min(1.0);
        let scaled = normalized_cumulative_probability * u64::MAX as f64;
        *bound = if scaled >= u64::MAX as f64 {
            u64::MAX
        } else {
            (scaled + 0.5) as u64
        };
    }

    // Force a terminal bound even if cumulative floating-point rounding falls below one.
    if let Some(last) = cdt.last_mut() {
        *last = u64::MAX;
    }

    (standard_deviation, cdt)
}
