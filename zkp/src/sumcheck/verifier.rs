//! Verifier for the multilinear sumcheck protocol
// It is derived from https://github.com/arkworks-rs/sumcheck/blob/master/src/ml_sumcheck/protocol/verifier.rs.

use std::vec;

use algebra::{utils::Transcript, Field, PolynomialInfo};

use crate::error::Error;

use super::{prover::ProverMsg, IPForMLSumcheck};

#[derive(Clone)]
/// verifier message
pub struct VerifierMsg<F: Field> {
    /// randomness sampled by verifier
    pub randomness: F,
}

/// Verifier State
pub struct VerifierState<F: Field> {
    round: usize,
    nv: usize,
    max_multiplicands: usize,
    finished: bool,
    /// a list storing the univariate polynomial in evaluations sent by the prover at each round
    polynomials_received: Vec<Vec<F>>,
    /// a list storing the randomness sampled by the verifier at each round
    randomness: Vec<F>,
}

/// Subclaim when verifier is convinced
#[derive(Default)]
pub struct SubClaim<F: Field> {
    /// the multi-dimensional point that this multilinear extension is evaluated to
    pub point: Vec<F>,
    /// the expected evaluation
    pub expected_evaluations: F,
}

impl<F: Field> IPForMLSumcheck<F> {
    /// initialize the verifier
    pub fn verifier_init(index_info: &PolynomialInfo) -> VerifierState<F> {
        VerifierState {
            round: 1,
            nv: index_info.num_variables,
            max_multiplicands: index_info.max_multiplicands,
            finished: false,
            polynomials_received: Vec::with_capacity(index_info.num_variables),
            randomness: Vec::with_capacity(index_info.num_variables),
        }
    }

    /// Run verifier at current round, given prover message.
    ///
    /// Normally, this function should perform actual verification. Instead, `verify_round` only samples
    /// and stores randomness and perform verifications altogether in `check_and_generate_subclaim` at
    /// the last step.
    pub fn verify_round(
        prover_msg: &ProverMsg<F>,
        verifier_state: &mut VerifierState<F>,
        trans: &mut Transcript<F>,
    ) -> Option<VerifierMsg<F>> {
        if verifier_state.finished {
            panic!("incorrect verifier state: Verifier is already finished.")
        }

        // Now, verifier should check if the received P(0) + P(1) = expected. The check is moved to
        // `check_and_generate_subclaim`, and will be done after the last round.
        let msg = Self::sample_round(trans);
        verifier_state.randomness.push(msg.randomness);
        verifier_state
            .polynomials_received
            .push(prover_msg.evaluations.clone());

        // Now, verifier should set `expected` to P(r).
        // This operation is also moved to `check_and_generate_subclaim`,
        // and will be done after the last round.
        if verifier_state.round == verifier_state.nv {
            // accept and close
            verifier_state.finished = true;
        } else {
            verifier_state.round += 1;
        }
        Some(msg)
    }

    /// check the proof and generate the reduced subclaim
    pub fn check_and_generate_subclaim(
        verifier_state: VerifierState<F>,
        asserted_sum: F,
    ) -> Result<SubClaim<F>, Error> {
        if !verifier_state.finished {
            panic!("Verifier has not finished.");
        }

        let mut expected = asserted_sum;
        if verifier_state.polynomials_received.len() != verifier_state.nv {
            panic!("insufficient rounds.");
        }
        for i in 0..verifier_state.nv {
            let evaluations = &verifier_state.polynomials_received[i];
            if evaluations.len() != verifier_state.max_multiplicands + 1 {
                panic!("incorrect number of evaluations");
            }
            let p0 = evaluations[0];
            let p1 = evaluations[1];
            if p0 + p1 != expected {
                return Err(Error::Reject(Some(
                    "Prover message is not consistent with the claim.".into(),
                )));
            }
            expected = interpolate_uni_poly(evaluations, verifier_state.randomness[i]);
        }

        Ok(SubClaim {
            point: verifier_state.randomness,
            expected_evaluations: expected,
        })
    }

    /// Simulate a verifier message without doing verification
    #[inline]
    pub fn sample_round(trans: &mut Transcript<F>) -> VerifierMsg<F> {
        VerifierMsg {
            randomness: trans.get_challenge(b"random point in each round"),
        }
    }
}

/// Interpolate the *unique* univariate polynomial of degree *at most*
/// p_i.len() - 1 passing through y-values in p_i at x = 0, ..., p_i.len() - 1,
/// and evaluate this polynomial at `eval_at`.
/// In other words, efficiently compute
/// \sum_{i=0}^{len p_i - 1} p_i\[i\] * (\prod_{j!=i}(eval_at - j)/(i - j))
pub(crate) fn interpolate_uni_poly<F: Field>(p_i: &[F], eval_at: F) -> F {
    let len = p_i.len();

    let mut evals = vec![];

    //`prod = \prod_{j} (eval - j)` for j = 0...len
    let mut prod = eval_at;
    evals.push(eval_at);

    let mut check = F::zero();
    // We return early if 0 <= eval_at <  len, i.e. if the desired value has been passed
    for i in 1..len {
        if eval_at == check {
            return p_i[i - 1];
        }
        check += F::one();

        let tmp = eval_at - check;
        evals.push(tmp);
        prod *= tmp;
    }
    if eval_at == check {
        return p_i[len - 1];
    }
    // Now check = len - 1

    let mut res = F::zero();
    // We want to compute the denominator \prod (j!=i) (i-j) for a given i in 0..len
    //
    // we start from the last step for i = len - 1, which is
    // denom[len-1] = (len-1) * (len-2) * ... * 2 * 1
    // the step before that is
    // denom[len-2] = (len-2) * (len-3) * ... * 2 * 1 * (-1)
    // and the step before that is
    // denom[len-3] = (len-3) * (len-4) * ... * 2 * 1 * (-1) * (-2)
    //
    // i.e., for any i, the one before this will be derived from
    // denom[i-1] = - denom[i] * (len-i) / i
    //
    // that is, we only need to store
    // - the last denom for i = len-1, and
    // - the ratio between the current step and the last step, which is the
    //   product of -(len-i) / i from all previous steps and we store
    //   this product as a fraction number to reduce field divisions.

    // We know
    // - 2^61 < factorial(20) < 2^62
    // - 2^122 < factorial(33) < 2^123
    // so we will be able to compute the ratio
    // - for len <= 20 with i64
    // - for len <=33 with i128
    // - for len > 33 with BigInt

    // TODO: We cannot implement the above optimization for now since we don't have the `from` trait, enabling us to directly convert a u64/u128 value to a field element.
    // Below is the plain implementation to compute
    // \sum_{i=0}^{len p_i - 1} p_i[i] * (\prod_{j!=i} (eval_at - j)/(i-j))
    // = \sum_{i=0}^{len p_i - 1} * (prod / evals[i]) / denom[i]
    // = \sum_{i=0}^{len p_i - 1} * prod / (evals[i] * denom[i]) where denom[i-1] = - denom[i] * (len-i) / i.
    // So we use denom_up / denom_down to update denom[i] in reverse.
    let mut denom_up = field_factorial::<F>(len - 1);
    let mut denom_down = F::one();

    let mut i_as_field = check; // len-1
    let mut len_minust_i_as_field = F::one();
    for i in (0..len).rev() {
        res += p_i[i] * prod * denom_down / (denom_up * evals[i]);

        // Update denom for the next step
        // denom[i-1] = - denom[i] * (len-i) / i.
        if i != 0 {
            denom_up *= -len_minust_i_as_field;
            denom_down *= i_as_field;
            i_as_field -= F::one();
            len_minust_i_as_field += F::one();
        }
    }
    res
}

/// Compute the factorial(a) = 1 * 2 * ... * a
#[inline]
fn field_factorial<F: Field>(a: usize) -> F {
    let mut res = F::one();
    let mut acc = F::one();
    for _i in 1..=a {
        res *= acc;
        acc += F::one();
    }
    res
}

#[cfg(test)]
mod test {
    use crate::sumcheck::verifier::interpolate_uni_poly;
    use algebra::{
        derive::{Field, Prime},
        Field, FieldUniformSampler, Polynomial,
    };
    use num_traits::{One, Zero};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use rand_distr::Distribution;

    #[derive(Field, Prime)]
    #[modulus = 132120577]
    pub struct Fp32(u32);

    // field type
    type FF = Fp32;
    type UniPolyFf = Polynomial<FF>;

    macro_rules! field_vec {
        ($t:ty; $elem:expr; $n:expr)=>{
            vec![<$t>::new($elem);$n]
        };
        ($t:ty; $($x:expr),+ $(,)?) => {
            vec![$(<$t>::new($x)),+]
        }
    }

    #[test]
    fn test_interpolation() {
        let mut prng = ChaCha12Rng::seed_from_u64(1953);

        // Test a polynomial with 20 known points, i.e., with degree 19
        let poly = UniPolyFf::random(20 - 1, &mut prng);

        let mut evals: Vec<FF> = Vec::with_capacity(20);
        let mut point = FF::zero();
        evals.push(poly.evaluate(point));
        for _i in 1..20 {
            point += FF::one();
            evals.push(poly.evaluate(point));
        }
        let query = <FieldUniformSampler<FF>>::new().sample(&mut prng);

        assert_eq!(poly.evaluate(query), interpolate_uni_poly(&evals, query));

        // Test interpolation when we ask for the value at an x-coordinate we are already passing,
        // i.e., in the range 0 <= x < len(values) - 1
        let evals = field_vec!(FF; 0, 1, 4, 9);
        assert_eq!(interpolate_uni_poly(&evals, FF::new(3)), FF::new(9));
    }
}
