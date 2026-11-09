//! Exact BFV bounds for a single working prefix.
use dashu_int::{UBig, ops::BitTest};
use primus_glwe_rns::rlwe_parameters::search_ntt_primes;

use crate::BfvContext;

use super::{BfvLeveledErrorLedger, BfvLeveledKeyBackend, BfvLeveledParameterError, bound_decimal};

fn ceil(a: UBig, b: UBig) -> UBig {
    (&a + &b - 1u8) / b
}
pub(super) fn words(v: &UBig) -> Vec<u64> {
    let mut x = v.clone();
    let mask = UBig::from(u64::MAX);
    let mut out = Vec::new();
    while x != UBig::ZERO {
        out.push(u64::try_from(&x & &mask).expect("masked word"));
        x >>= 64;
    }
    if out.is_empty() {
        out.push(0);
    }
    out
}

pub(super) struct LayerBounds {
    reduced_input: UBig,
    converted_right: UBig,
    left_quotient: UBig,
    right_quotient: UBig,
    product: UBig,
    rounding: UBig,
    restored: UBig,
    drift: UBig,
    pub(super) output_error: UBig,
}

pub(super) struct Candidate {
    n: usize,
    t: u64,
    h: u64,
    pub(super) keep: usize,
    q: UBig,
    p: UBig,
    d: UBig,
    r: u64,
    key_sampling: UBig,
    key_residual: UBig,
    key_error: UBig,
    pub(super) auxiliary: Vec<u64>,
}
impl Candidate {
    pub(super) fn new(
        context: &BfvContext,
        keep: usize,
        backend: BfvLeveledKeyBackend,
        h: u64,
        eta: u64,
        key_p: &[u64],
        full_q: &UBig,
    ) -> Result<Self, BfvLeveledParameterError> {
        let parameters = context.parameters();
        let n = parameters.poly_length().get();
        let t = parameters.codec().t();
        let qs = parameters.base_q().moduli_values();
        let active_basis = context.codec(qs.len() - keep).base_q();
        let q = bound_decimal(active_basis.moduli_product().0);
        let lower =
            (UBig::from(4u8) * t * t * n * keep * UBig::from(h + 1) * (h + 1)).max(q.clone());
        let primes = search_ntt_primes(n, 60, lower.bit_len().div_ceil(59), None, qs)?;
        let mut auxiliary = Vec::new();
        let mut p = UBig::ONE;
        for prime in primes {
            if p >= lower {
                break;
            }
            auxiliary.push(prime);
            p *= prime;
        }
        let (key_sampling, key_residual, key_error) = match backend {
            BfvLeveledKeyBackend::Radix16 => {
                let digits = q.bit_len() / 16;
                let rem = q.bit_len() % 16;
                let sampling = UBig::from(n) * digits * (1u64 << 15) * eta;
                let residual = if rem == 0 {
                    UBig::ZERO
                } else {
                    UBig::from(h) * h * (1u64 << (rem - 1))
                };
                let total = &sampling + &residual;
                (sampling, residual, total)
            }
            BfvLeveledKeyBackend::HybridAlpha1 => {
                let p: UBig = key_p.iter().copied().map(UBig::from).product();
                let numerator = UBig::from(n)
                    * eta
                    * qs[..keep].iter().fold(UBig::ZERO, |sum, &x| sum + x - 1u8);
                let sampling = ceil(numerator.clone(), p.clone());
                let residual = ceil(UBig::from(h + 1), UBig::from(2u8));
                let total = ceil(numerator * 2u8 + UBig::from(h + 1) * &p, p * 2u8);
                (sampling, residual, total)
            }
        };
        Ok(Self {
            n,
            t,
            h,
            keep,
            d: full_q / &q,
            r: full_q % t,
            q,
            p,
            key_sampling,
            key_residual,
            key_error,
            auxiliary,
        })
    }
    pub(super) fn evaluate(&self, e: &UBig) -> LayerBounds {
        // Rational q/t phases retain their integer quotients and HPS wrap.
        // Every displayed ceil is part of the public deterministic model.
        let h = self.h;
        let m = self.t / 2;
        let h1 = h + 1;
        let u = ceil(
            (e * self.t + UBig::from(self.r) * m) * 2u8 + &self.d * self.t * h1,
            &self.d * self.t * 2u8,
        );
        let v = ceil(&self.p * &u, self.q.clone()) + UBig::from(self.keep) * h1;
        let za = ceil(
            (UBig::from(h1) * self.t + UBig::from(2u8) * m) * &self.q + &u * self.t * 2u8,
            &self.q * self.t * 2u8,
        );
        let zb = ceil(
            (UBig::from(h1) * self.t + UBig::from(2u8) * m) * &self.p + &v * self.t * 2u8,
            &self.p * self.t * 2u8,
        );
        let product = ceil(
            (&self.q * (UBig::from(m) + &za * self.t) * &v
                + &self.p * &u * (UBig::from(m) + &zb * self.t)
                + UBig::from(self.t) * &u * &v)
                * self.n,
            self.p.clone(),
        );
        let rounding = ceil(UBig::ONE + h + UBig::from(h) * h, UBig::from(2u8));
        let restored = &self.d * (&product + &rounding + &self.key_error);
        let drift = ceil(UBig::from(self.r) * m, UBig::from(self.t));
        LayerBounds {
            reduced_input: u,
            converted_right: v,
            left_quotient: za,
            right_quotient: zb,
            product,
            rounding,
            output_error: &restored + &drift,
            restored,
            drift,
        }
    }

    pub(super) fn output(&self, e: &UBig) -> UBig {
        self.evaluate(e).output_error
    }

    pub(super) fn ledger(&self, bounds: &LayerBounds, capacity: &UBig) -> BfvLeveledErrorLedger {
        BfvLeveledErrorLedger {
            working_modulus: words(&self.q),
            restoration_multiplier: words(&self.d),
            computation_auxiliary_product: words(&self.p),
            reduced_input_error: words(&bounds.reduced_input),
            converted_right_error: words(&bounds.converted_right),
            left_phase_quotient: words(&bounds.left_quotient),
            right_phase_quotient: words(&bounds.right_quotient),
            product_error: words(&bounds.product),
            component_rounding_error: words(&bounds.rounding),
            key_sampling_error: words(&self.key_sampling),
            key_residual_or_moddown_error: words(&self.key_residual),
            key_error: words(&self.key_error),
            restored_error: words(&bounds.restored),
            restoration_drift: words(&bounds.drift),
            output_error: words(&bounds.output_error),
            decoder_capacity: words(capacity),
            remaining_error_capacity: words(&(capacity - &bounds.output_error)),
        }
    }
}
