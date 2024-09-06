//! Round IOP
//! The round operation is the scaling operation, followed by a floor operation.
//!
//! The round operation takes as input a \in F_Q and outputs b \in Zq such that b = \floor (a * q) / Q.
//! In some senses, this operation maps an interval of F_Q into an element of Zq.
//!
//! The prover is going to prove: for x \in {0, 1}^\logM
//! 1. b(x) \in [q] -> which can be proven with a range check since q is a power-of-two
//! 2. c(x) \in [1, ..., k]
//!     meant to prove c(x) - 1 \in [k]
//!     Let L denote the logarithm of the next power-of-two number that is bigger or equal to k.
//!     Let delta denote 2^L - k
//!     It is necessary to be proven with 2 range checks:
//!         one is to prove c(x) - 1 \in [2^L]
//!         the other is to prove c(x) - 1 + delta \in [2^L]
//! 3. w(x)(1 - w(x)) = 0 where w indicates the option in the following constraint
//! 4. w(x)(a(x)\cdot \lambda_1+b(x)\cdot \lambda_2)+(1-w(x))(a(x)-b(x)\cdot k-c(x))=0
//!     where \lambda_1 and \lambda_2 are chosen by the verifier
use super::bit_decomposition::{BitDecomposition, DecomposedBitsEval};
use super::{DecomposedBits, DecomposedBitsInfo};
use crate::sumcheck::verifier::SubClaim;
use crate::sumcheck::{MLSumcheck, ProofWrapper, SumcheckKit};
use crate::sumcheck::Proof;
use crate::utils::eval_identity_function;
use crate::utils::gen_identity_evaluations;
use algebra::{
    utils::Transcript, AbstractExtensionField, DecomposableField, DenseMultilinearExtension, Field,
    ListOfProductsOfPolynomials, MultilinearExtension, PolynomialInfo,
};
use core::fmt;
use itertools::izip;
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{LinearCode, LinearCodeSpec},
    utils::hash::Hash,
    PolynomialCommitmentScheme,
};
use serde::Serialize;
use std::marker::PhantomData;
use std::rc::Rc;
use std::vec;

/// Round IOP
pub struct RoundIOP<F: Field>(PhantomData<F>);
/// SNARKs for Round compiled with PCS
// pub struct RoundSnarks<F: Field>(PhantomData<F>, PhantomData<EF>);

/// Round Instance used as prover keys
pub struct RoundInstance<F: Field> {
    /// number of variables
    pub num_vars: usize,
    /// k = Q - 1 / q where q is the modulus of the output
    pub k: F,
    /// delta = 2^{k_bit_len} - k
    pub delta: F,
    /// input denoted by a \in F_Q
    pub input: Rc<DenseMultilinearExtension<F>>,
    /// output denoted by b \in F_q
    pub output: Rc<DenseMultilinearExtension<F>>,
    /// decomposed bits of output used for range check
    pub output_bits: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// decomposition info for outputs
    pub output_bits_info: DecomposedBitsInfo<F>,

    /// offset denoted by c = a - b * k \in [1, k] such that c - 1 \in [0, k)
    pub offset: Rc<DenseMultilinearExtension<F>>,
    /// offset_aux_bits contains two instances of bit decomposition
    /// decomposed bits of c - 1 \in [0, 2^k_bit_len) used for range check
    /// decomposed bits of c - 1 + delta \in [0, 2^k_bit_len) used for range check
    pub offset_aux_bits: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// decomposition info for offset
    pub offset_bits_info: DecomposedBitsInfo<F>,
    /// option denoted by w \in {0, 1}
    pub option: Rc<DenseMultilinearExtension<F>>,
}

/// Evaluation at a random point
pub struct RoundInstanceEval<F: Field> {
    /// input denoted by a \in F_Q
    pub input: F,
    /// output denoted by b \in F_q
    pub output: F,
    /// decomposed bits of output used for range check
    pub output_bits: Vec<F>,
    /// offset denoted by c = a - b * k \in [1, k] such that c - 1 \in [0, k)
    pub offset: F,
    /// offset_aux = offset - 1 and offset - 1 - delta
    pub offset_aux: Vec<F>,
    /// offset_aux_bits contains two instances of bit decomposition
    /// decomposed bits of c - 1 \in [0, 2^k_bit_len) used for range check
    /// decomposed bits of c - 1 + delta \in [0, 2^k_bit_len) used for range check
    pub offset_aux_bits: Vec<F>,
    /// option denoted by w \in {0, 1}
    pub option: F,
}

/// Information about Round Instance used as verifier keys
pub struct RoundInstanceInfo<F: Field> {
    /// number of variables
    pub num_vars: usize,
    /// k = Q - 1 / q is the modulus of the output
    pub k: F,
    /// delta = 2^k_bits_len - k
    pub delta: F,
    /// decomposition info for outputs
    pub output_bits_info: DecomposedBitsInfo<F>,
    /// decomposition info for offset
    pub offset_bits_info: DecomposedBitsInfo<F>,
}

impl<F: Field> fmt::Display for RoundInstance<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "An instance of Round from Q to q: #vars = {}",
            self.num_vars,
        )?;
        write!(f, "- containing ")?;
        self.output_bits_info.fmt(f)?;
        self.offset_bits_info.fmt(f)
    }
}

impl<F: Field> RoundInstance<F> {
    /// Extract the information
    #[inline]
    pub fn info(&self) -> RoundInstanceInfo<F> {
        RoundInstanceInfo {
            num_vars: self.num_vars,
            k: self.k,
            delta: self.delta,
            output_bits_info: self.output_bits_info.clone(),
            offset_bits_info: self.offset_bits_info.clone(),
        }
    }

    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        4 + self.output_bits.len() + self.offset_aux_bits.len()
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_oracles(&self) -> usize {
        self.num_oracles().next_power_of_two().ilog2() as usize
    }

    /// Pack all the involved small polynomials into a single vector of evaluations without padding
    pub fn pack_all_mles(&self) -> Vec<F> {
        self.input
            .iter()
            .chain(self.output.iter())
            .chain(self.offset.iter())
            .chain(self.option.iter())
            .chain(self.output_bits.iter().flat_map(|bit| bit.iter()))
            .chain(self.offset_aux_bits.iter().flat_map(|bit| bit.iter()))
            .copied()
            .collect::<Vec<F>>()
    }

    /// Generate the oracle to be committed that is composed of all the small oracles used in IOP.
    /// The evaluations of this oracle is generated by the evaluations of all mles and the padded zeros.
    /// The arrangement of this oracle should be consistent to its usage in verifying the subclaim.
    pub fn generate_oracle(&self) -> DenseMultilinearExtension<F> {
        let num_vars_added = self.log_num_oracles();
        let num_vars = self.num_vars + num_vars_added;
        let num_zeros_padded = ((1 << num_vars_added) - self.num_oracles()) * (1 << self.num_vars);

        // arrangement: all values||all decomposed bits||padded zeros
        let mut evals = self.pack_all_mles();
        evals.append(&mut vec![F::zero(); num_zeros_padded]);
        <DenseMultilinearExtension<F>>::from_evaluations_vec(num_vars, evals)
    }

    /// Construct a EF version
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> RoundInstance<EF> {
        RoundInstance::<EF> {
            num_vars: self.num_vars,
            k: EF::from_base(self.k),
            delta: EF::from_base(self.delta),
            input: Rc::new(self.input.to_ef::<EF>()),
            output: Rc::new(self.output.to_ef::<EF>()),
            offset: Rc::new(self.offset.to_ef::<EF>()),
            option: Rc::new(self.option.to_ef::<EF>()),
            output_bits: self
                .output_bits
                .iter()
                .map(|bit| Rc::new(bit.to_ef()))
                .collect(),
            offset_aux_bits: self
                .offset_aux_bits
                .iter()
                .map(|bit| Rc::new(bit.to_ef()))
                .collect(),
            output_bits_info: self.output_bits_info.to_ef::<EF>(),
            offset_bits_info: self.offset_bits_info.to_ef::<EF>(),
        }
    }

    /// Evaluate at a random point defined over Field
    #[inline]
    pub fn evaluate(&self, point: &[F]) -> RoundInstanceEval<F> {
        let offset = self.offset.evaluate(point);
        RoundInstanceEval::<F> {
            input: self.input.evaluate(point),
            output: self.output.evaluate(point),
            offset,
            option: self.option.evaluate(point),
            output_bits: self
                .output_bits
                .iter()
                .map(|bit| bit.evaluate(point))
                .collect(),
            offset_aux: vec![offset - F::one(), offset - F::one() + self.delta],
            offset_aux_bits: self
                .offset_aux_bits
                .iter()
                .map(|bit| bit.evaluate(point))
                .collect(),
        }
    }

    /// Evaluate at a random point defined over Extension Field
    #[inline]
    pub fn evaluate_ext<EF: AbstractExtensionField<F>>(
        &self,
        point: &[EF],
    ) -> RoundInstanceEval<EF> {
        let offset = self.offset.evaluate_ext(point);
        RoundInstanceEval::<EF> {
            input: self.input.evaluate_ext(point),
            output: self.output.evaluate_ext(point),
            offset,
            option: self.option.evaluate_ext(point),
            output_bits: self
                .output_bits
                .iter()
                .map(|bit| bit.evaluate_ext(point))
                .collect(),
            offset_aux: vec![offset - F::one(), offset - F::one() + self.delta],
            offset_aux_bits: self
                .offset_aux_bits
                .iter()
                .map(|bit| bit.evaluate_ext(point))
                .collect(),
        }
    }

    /// Extract DecomposedBits instance
    #[inline]
    pub fn extract_decomposed_bits(&self) -> (DecomposedBits<F>, DecomposedBits<F>) {
        // c - 1
        let c_minus_one = DenseMultilinearExtension::from_evaluations_vec(
            self.num_vars,
            self.offset.iter().map(|x| *x - F::one()).collect(),
        );
        // c - 1 + delta
        let c_minus_one_delta = DenseMultilinearExtension::from_evaluations_vec(
            self.num_vars,
            c_minus_one.iter().map(|x| *x + self.delta).collect(),
        );
        (
            DecomposedBits {
                base: self.output_bits_info.base,
                base_len: self.output_bits_info.base_len,
                bits_len: self.output_bits_info.bits_len,
                num_vars: self.num_vars,
                d_val: vec![Rc::clone(&self.output)],
                d_bits: self.output_bits.to_owned(),
            },
            DecomposedBits {
                base: self.offset_bits_info.base,
                base_len: self.offset_bits_info.base_len,
                bits_len: self.offset_bits_info.bits_len,
                num_vars: self.num_vars,
                d_val: vec![Rc::new(c_minus_one), Rc::new(c_minus_one_delta)],
                d_bits: self.offset_aux_bits.to_owned(),
            },
        )
    }
}

impl<F: DecomposableField> RoundInstance<F> {
    /// Compute the witness required in proof and construct the instance
    #[inline]
    pub fn new(
        k: F,
        delta: F,
        input: Rc<DenseMultilinearExtension<F>>,
        output: Rc<DenseMultilinearExtension<F>>,
        output_bits_info: &DecomposedBitsInfo<F>,
        offset_bits_info: &DecomposedBitsInfo<F>,
    ) -> Self {
        let num_vars = input.num_vars;
        assert_eq!(num_vars, output.num_vars);
        assert_eq!(num_vars, output_bits_info.num_vars);
        assert_eq!(num_vars, offset_bits_info.num_vars);
        assert_eq!(1, output_bits_info.num_instances);
        assert_eq!(2, offset_bits_info.num_instances);

        let output_bits =
            output.get_decomposed_mles(output_bits_info.base_len, output_bits_info.bits_len);

        // set w = 1 iff a = 0 & b = 0
        let option = Rc::new(DenseMultilinearExtension::<F>::from_evaluations_vec(
            num_vars,
            input
                .iter()
                .zip(output.iter())
                .map(|(a, b)| match (a.is_zero(), b.is_zero()) {
                    (true, true) => F::one(),
                    _ => F::zero(),
                })
                .collect(),
        ));

        // Note that we must set c \in [1, k] when w = 1 to ensure that c(x) \in [1, k] for all x \in {0,1}^logn
        // if w = 0: c = a - b * k
        // if w = 1: c = 1 defaultly
        let offset = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            izip!(option.iter(), input.iter(), output.iter())
                .map(|(w, a, b)| match w.is_zero() {
                    true => *a - *b * k,
                    false => F::one(),
                })
                .collect(),
        ));

        // c - 1
        let c_minus_one = DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            offset.iter().map(|x| *x - F::one()).collect(),
        );
        let mut offset_aux_bits =
            c_minus_one.get_decomposed_mles(offset_bits_info.base_len, offset_bits_info.bits_len);
        // c - 1 + delta
        let c_minus_one_delta = DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            c_minus_one.iter().map(|x| *x + delta).collect(),
        );
        let mut c_minus_one_delta_bits = c_minus_one_delta
            .get_decomposed_mles(offset_bits_info.base_len, offset_bits_info.bits_len);
        offset_aux_bits.append(&mut c_minus_one_delta_bits);

        Self {
            num_vars,
            k,
            delta,
            input,
            output,
            output_bits,
            offset,
            offset_aux_bits,
            option,
            offset_bits_info: offset_bits_info.clone(),
            output_bits_info: output_bits_info.clone(),
        }
    }
}

impl<F: Field> RoundInstanceEval<F> {
    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        4 + self.output_bits.len() + self.offset_aux_bits.len()
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_oracles(&self) -> usize {
        self.num_oracles().next_power_of_two().ilog2() as usize
    }

    /// Flatten all evals into a vector with the same arrangement of the committed polynomial
    #[inline]
    pub fn flatten(&self) -> Vec<F> {
        let mut res = Vec::with_capacity(self.num_oracles());
        res.push(self.input);
        res.push(self.output);
        res.push(self.offset);
        res.push(self.option);
        res.extend(self.output_bits.iter());
        res.extend(self.offset_aux_bits.iter());
        res
    }

    /// Extract DecomposedBitsEval instance
    #[inline]
    pub fn extract_decomposed_bits(&self) -> (DecomposedBitsEval<F>, DecomposedBitsEval<F>) {
        (
            DecomposedBitsEval {
                d_val: vec![self.output],
                d_bits: self.output_bits.to_owned(),
            },
            DecomposedBitsEval {
                d_val: self.offset_aux.to_owned(),
                d_bits: self.offset_aux_bits.to_owned(),
            },
        )
    }
}

impl<F: Field + Serialize> RoundIOP<F> {
    /// sample coins before proving sumcheck protocol
    pub fn sample_coins(trans: &mut Transcript<F>, instance: &RoundInstance<F>) -> Vec<F> {
        trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            <BitDecomposition<F>>::num_coins(&instance.output_bits_info)
                + <BitDecomposition<F>>::num_coins(&instance.offset_bits_info)
                + 4,
        )
    }

    /// return the number of coins used in this IOP
    pub fn num_coins(info: &RoundInstanceInfo<F>) -> usize {
        <BitDecomposition<F>>::num_coins(&info.output_bits_info)
            + <BitDecomposition<F>>::num_coins(&info.offset_bits_info)
            + 4
    }

    /// Prove round
    pub fn prove(instance: &RoundInstance<F>) -> SumcheckKit<F>
    {
        let mut trans = Transcript::<F>::new();
        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );

        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);
        let randomness = Self::sample_coins(&mut trans, &instance);
        Self::prove_as_subprotocol(&randomness, &mut poly, &instance, &u);

        let (proof, state) = MLSumcheck::prove_as_subprotocol(&mut trans, &poly)
            .expect("fail to prove the sumcheck protocol");
        // (proof, state, poly.info())
        SumcheckKit {
            proof,
            info: poly.info(),
            claimed_sum: F::zero(),
            randomness: state.randomness,
            u,
        }
    }

    /// Prove round
    pub fn prove_as_subprotocol(
        randomness: &[F],
        poly: &mut ListOfProductsOfPolynomials<F>,
        instance: &RoundInstance<F>,
        u: &[F],
    ) {
        let (output_bits_instance, offset_bits_instance) = instance.extract_decomposed_bits();
        let output_bits_r_num = <BitDecomposition<F>>::num_coins(&instance.output_bits_info);
        let offset_bits_r_num = <BitDecomposition<F>>::num_coins(&instance.offset_bits_info);
        assert_eq!(randomness.len(), output_bits_r_num + offset_bits_r_num + 4);
        // 1. add products used to prove decomposition
        BitDecomposition::prove_as_subprotocol(
            &randomness[..output_bits_r_num],
            poly,
            &output_bits_instance,
            u,
        );
        BitDecomposition::prove_as_subprotocol(
            &randomness[output_bits_r_num..output_bits_r_num + offset_bits_r_num],
            poly,
            &offset_bits_instance,
            u,
        );

        let identity_func_at_u = Rc::new(gen_identity_evaluations(u));
        let lambda_1 = randomness[randomness.len() - 4];
        let lambda_2 = randomness[randomness.len() - 3];
        let r_1 = randomness[randomness.len() - 2];
        let r_2 = randomness[randomness.len() - 1];
        // 2. add sumcheck1 for \sum_{x} eq(u, x) * w(x) * (1-w(x)) = 0, i.e. w(x)\in\{0,1\}^l with random coefficient r_1
        poly.add_product_with_linear_op(
            [
                Rc::clone(&identity_func_at_u),
                Rc::clone(&instance.option),
                Rc::clone(&instance.option),
            ],
            &[
                (F::one(), F::zero()),
                (F::one(), F::zero()),
                (-F::one(), F::one()),
            ],
            r_1,
        );

        // 3. add sumcheck2 for \sum_{x} eq(u, x) * [w(x) * (a(x) * \lambda_1 + b(x) * \lambda_2)+(1 - w(x)) * (a(x) - b(x) * k - c(x))]=0
        // with random coefficient r_2 where \lambda_1 and \lambda_2 are chosen by the verifier

        // The following steps add five products composing the function in the above sumcheck protocol
        // product: eq(u, x) * w(x) * (a(x) * \lambda_1)
        poly.add_product_with_linear_op(
            [
                Rc::clone(&identity_func_at_u),
                Rc::clone(&instance.option),
                Rc::clone(&instance.input),
            ],
            &[
                (F::one(), F::zero()),
                (F::one(), F::zero()),
                (lambda_1, F::zero()),
            ],
            r_2,
        );
        // product: eq(u, x) * w(x) * (b(x) * \lambda_2)
        poly.add_product_with_linear_op(
            [
                Rc::clone(&identity_func_at_u),
                Rc::clone(&instance.option),
                Rc::clone(&instance.output),
            ],
            &[
                (F::one(), F::zero()),
                (F::one(), F::zero()),
                (lambda_2, F::zero()),
            ],
            r_2,
        );
        // product: eq(u, x) * (1 - w(x)) * a(x)
        poly.add_product_with_linear_op(
            [
                Rc::clone(&identity_func_at_u),
                Rc::clone(&instance.option),
                Rc::clone(&instance.input),
            ],
            &[
                (F::one(), F::zero()),
                (-F::one(), F::one()),
                (F::one(), F::zero()),
            ],
            r_2,
        );
        // product: eq(u, x) * (1 - w(x)) * (-k * b(x))
        poly.add_product_with_linear_op(
            [
                Rc::clone(&identity_func_at_u),
                Rc::clone(&instance.option),
                Rc::clone(&instance.output),
            ],
            &[
                (F::one(), F::zero()),
                (-F::one(), F::one()),
                (-instance.k, F::zero()),
            ],
            r_2,
        );
        // product: eq(u, x) * (1 - w(x)) * (-c(x))
        poly.add_product_with_linear_op(
            [
                Rc::clone(&identity_func_at_u),
                Rc::clone(&instance.option),
                Rc::clone(&instance.offset),
            ],
            &[
                (F::one(), F::zero()),
                (-F::one(), F::one()),
                (-F::one(), F::zero()),
            ],
            r_2,
        );
    }

    /// Verify addition in Zq
    pub fn verify(
        wrapper: &ProofWrapper<F>,
        evals: &RoundInstanceEval<F>,
        info: &RoundInstanceInfo<F>,
    ) -> bool {
        let mut trans = Transcript::new();

        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            info.num_vars,
        );

        // randomness to combine sumcheck protocols
        let randomness = trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            Self::num_coins(info),
        );

        let mut subclaim =
            MLSumcheck::verify_as_subprotocol(&mut trans, &wrapper.info, F::zero(), &wrapper.proof)
                .expect("fail to verify the sumcheck protocol");

        if !Self::verify_as_subprotocol(&randomness, &mut subclaim, evals, info, &u) {
            return false;
        }

        subclaim.expected_evaluations == F::zero()
    }

    /// Verify round
    pub fn verify_as_subprotocol(
        randomness: &[F],
        subclaim: &mut SubClaim<F>,
        evals: &RoundInstanceEval<F>,
        info: &RoundInstanceInfo<F>,
        u: &[F],
    ) -> bool {
        let (output_bits_evals, offset_bits_evals) = evals.extract_decomposed_bits();
        let output_bits_r_num = <BitDecomposition<F>>::num_coins(&info.output_bits_info);
        let offset_bits_r_num = <BitDecomposition<F>>::num_coins(&info.offset_bits_info);
        assert_eq!(randomness.len(), output_bits_r_num + offset_bits_r_num + 4);
        let check_output_bits = <BitDecomposition<F>>::verify_as_subprotocol(
            &randomness[..output_bits_r_num],
            subclaim,
            &output_bits_evals,
            &info.output_bits_info,
            u,
        );
        let check_offset_bits = <BitDecomposition<F>>::verify_as_subprotocol(
            &randomness[output_bits_r_num..output_bits_r_num + offset_bits_r_num],
            subclaim,
            &offset_bits_evals,
            &info.offset_bits_info,
            u,
        );
        if !(check_output_bits && check_offset_bits) {
            return false;
        }
        let lambda_1 = randomness[randomness.len() - 4];
        let lambda_2 = randomness[randomness.len() - 3];
        let r_1 = randomness[randomness.len() - 2];
        let r_2 = randomness[randomness.len() - 1];
        let eq_eval = eval_identity_function(u, &subclaim.point);

        // check 2: check the subclaim returned from the sumcheck protocol
        subclaim.expected_evaluations -= r_1 * eq_eval * evals.option * (F::one() - evals.option);
        subclaim.expected_evaluations -= r_2
            * eq_eval
            * (evals.option * (evals.input * lambda_1 + evals.output * lambda_2)
                + (F::one() - evals.option) * (evals.input - evals.output * info.k - evals.offset));
        true
    }
}


