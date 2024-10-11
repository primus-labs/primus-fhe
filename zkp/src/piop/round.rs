//! Round IOP
use super::{
    BitDecompositionEval, BitDecompositionIOP, BitDecompositionInstance,
    BitDecompositionInstanceInfo,
};
use crate::sumcheck::verifier::SubClaim;
use crate::sumcheck::{MLSumcheck, ProofWrapper, SumcheckKit};
use crate::utils::{
    eval_identity_function, gen_identity_evaluations, print_statistic, verify_oracle_relation,
};
use algebra::{
    utils::Transcript, AbstractExtensionField, DecomposableField, DenseMultilinearExtension, Field,
    ListOfProductsOfPolynomials,
};
use core::fmt;
use itertools::izip;
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{LinearCode, LinearCodeSpec},
    utils::hash::Hash,
    PolynomialCommitmentScheme,
};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::rc::Rc;
use std::time::Instant;
use std::vec;

/// Round IOP
pub struct RoundIOP<F: Field>(PhantomData<F>);
/// SNARKs for Round compiled with PCS
pub struct RoundSnarks<F: Field, EF: AbstractExtensionField<F>>(PhantomData<F>, PhantomData<EF>);

/// Round Instance used as prover keys
pub struct RoundInstance<F: Field> {
    /// number of variables
    pub num_vars: usize,
    /// modulus q
    pub q: F,
    /// k = Q - 1 / 2q where q is the modulus of the output
    pub k: F,

    /// Let 2k_len denotes the bit length of 2k
    /// delta = 2^{2k_len} - k
    pub delta: F,
    /// input denoted by a \in F_Q
    pub input: Rc<DenseMultilinearExtension<F>>,

    /// We introduce b' and e such that b' = b + e * q
    /// output denoted by b \in F_q
    pub output: Rc<DenseMultilinearExtension<F>>,
    /// auxiliary output denoted by b' \in {1, ..., q} satisfying b = b' (mod q)
    pub output_aux: Rc<DenseMultilinearExtension<F>>,
    /// witness for molular operation denoted by e \in {0, 1}
    pub output_mod: Rc<DenseMultilinearExtension<F>>,
    /// decomposed bits of output and auxiliary output used for range check
    pub output_bits: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// decomposition info for outputs in [q]
    pub output_bits_info: BitDecompositionInstanceInfo<F>,

    /// offset denoted by c = a - b * k \in [1, 2k] such that c - 1 \in [0, k)
    pub offset: Rc<DenseMultilinearExtension<F>>,
    /// offset_aux_bits contains two instances of bit decomposition
    /// decomposed bits of c - 1 \in [0, 2^2k_len) used for range check
    /// decomposed bits of c - 1 + delta \in [0, 2^2k_len) used for range check
    pub offset_aux_bits: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// decomposition info for offset
    pub offset_bits_info: BitDecompositionInstanceInfo<F>,
    /// option denoted by w \in {0, 1}
    pub option: Rc<DenseMultilinearExtension<F>>,
}

/// Evaluation at a random point
pub struct RoundInstanceEval<F: Field> {
    /// input denoted by a \in F_Q
    pub input: F,
    /// output denoted by b \in F_q
    pub output: F,
    /// auxiliary output denoted by b' \in {1, ..., q} satisfying b = b' (mod q)
    pub output_aux: F,
    /// witness for molular operation denoted by e \in {0, 1}
    pub output_mod: F,
    /// output and output_aux - 1
    pub output_all: Vec<F>,
    /// decomposed bits of output and auxiliary output used for range check
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
    /// modulus q
    pub q: F,
    /// k = Q - 1 / 2q is the modulus of the output
    pub k: F,
    /// Let 2k_len denotes the bit length of 2k
    /// delta = 2^{2k_len} - k
    pub delta: F,
    /// decomposition info for outputs
    pub output_bits_info: BitDecompositionInstanceInfo<F>,
    /// decomposition info for offset
    pub offset_bits_info: BitDecompositionInstanceInfo<F>,
}

impl<F: Field> fmt::Display for RoundInstanceInfo<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "An instance of Round from Q to q: #vars = {}",
            self.num_vars,
        )?;
        write!(f, "- containing ")?;
        self.output_bits_info.fmt(f)?;
        write!(f, "\n- containing ")?;
        self.offset_bits_info.fmt(f)
    }
}

impl<F: Field> RoundInstance<F> {
    /// Extract the information
    #[inline]
    pub fn info(&self) -> RoundInstanceInfo<F> {
        RoundInstanceInfo {
            num_vars: self.num_vars,
            q: self.q,
            k: self.k,
            delta: self.delta,
            output_bits_info: self.output_bits_info.clone(),
            offset_bits_info: self.offset_bits_info.clone(),
        }
    }

    /// Return the number of small polynomials used in IOP
    #[inline]
    pub fn num_oracles(&self) -> usize {
        6 + self.output_bits.len() + self.offset_aux_bits.len()
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
            .chain(self.output_aux.iter())
            .chain(self.output_mod.iter())
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
            q: EF::from_base(self.q),
            k: EF::from_base(self.k),
            delta: EF::from_base(self.delta),
            input: Rc::new(self.input.to_ef::<EF>()),
            output: Rc::new(self.output.to_ef::<EF>()),
            output_aux: Rc::new(self.output_aux.to_ef::<EF>()),
            output_mod: Rc::new(self.output_mod.to_ef::<EF>()),
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
        let output = self.output.evaluate(point);
        let output_aux = self.output_aux.evaluate(point);
        RoundInstanceEval::<F> {
            input: self.input.evaluate(point),
            output,
            output_aux,
            output_mod: self.output_mod.evaluate(point),
            output_all: vec![output, output_aux - F::one()],
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
        let output = self.output.evaluate_ext(point);
        let output_aux = self.output_aux.evaluate_ext(point);
        RoundInstanceEval::<EF> {
            input: self.input.evaluate_ext(point),
            output,
            output_aux,
            output_mod: self.output_mod.evaluate_ext(point),
            output_all: vec![output, output_aux - F::one()],
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
    pub fn extract_decomposed_bits(
        &self,
    ) -> (BitDecompositionInstance<F>, BitDecompositionInstance<F>) {
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

        // b' - 1
        let b_plus_minus_one = DenseMultilinearExtension::from_evaluations_vec(
            self.num_vars,
            self.output_aux.iter().map(|x| *x - F::one()).collect(),
        );
        (
            BitDecompositionInstance {
                base: self.output_bits_info.base,
                base_len: self.output_bits_info.base_len,
                bits_len: self.output_bits_info.bits_len,
                num_vars: self.num_vars,
                d_val: vec![Rc::clone(&self.output), Rc::new(b_plus_minus_one)],
                d_bits: self.output_bits.to_owned(),
            },
            BitDecompositionInstance {
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
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn new(
        num_vars: usize,
        q: F,
        k: F,
        delta: F,
        input: Rc<DenseMultilinearExtension<F>>,
        output: Rc<DenseMultilinearExtension<F>>,
        output_bits_info: &mut BitDecompositionInstanceInfo<F>,
        offset_bits_info: &mut BitDecompositionInstanceInfo<F>,
    ) -> Self {
        assert_eq!(num_vars, output.num_vars);
        assert_eq!(num_vars, output_bits_info.num_vars);
        assert_eq!(num_vars, offset_bits_info.num_vars);

        output_bits_info.num_instances = 2;
        let mut output_bits =
            output.get_decomposed_mles(output_bits_info.base_len, output_bits_info.bits_len);

        // zero MLE
        let mut output_aux = DenseMultilinearExtension::<F>::new(num_vars);
        let mut output_mod = DenseMultilinearExtension::<F>::new(num_vars);
        for (b, b_prime, mod_q) in
            izip!(output.iter(), output_aux.iter_mut(), output_mod.iter_mut())
        {
            if *b == F::zero() {
                *b_prime = q;
                *mod_q = F::one();
            } else {
                *b_prime = *b;
                // mod_q is F::zero();
            }
        }
        let output_aux_minus_one = DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            output_aux.iter().map(|x| *x - F::one()).collect::<Vec<_>>(),
        );
        output_bits.append(
            &mut output_aux_minus_one
                .get_decomposed_mles(output_bits_info.base_len, output_bits_info.bits_len),
        );

        // set w = 1 iff a = k & b = 0
        let option = Rc::new(DenseMultilinearExtension::<F>::from_evaluations_vec(
            num_vars,
            input
                .iter()
                .zip(output.iter())
                .map(|(a, b)| match ((*a - k).is_zero(), b.is_zero()) {
                    (true, true) => F::one(),
                    _ => F::zero(),
                })
                .collect(),
        ));

        // Note that we must set c \in [1, k] when w = 1 to ensure that c(x) \in [1, k] for all x \in {0,1}^logn
        // if w = 0: c = a - b * k
        // if w = 1: c = 1 defaultly
        let f_two = F::one() + F::one();
        offset_bits_info.num_instances = 2;
        let offset = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            izip!(option.iter(), input.iter(), output_aux.iter())
                .map(|(w, a, b_prime)| match w.is_zero() {
                    true => *a - (f_two * b_prime - F::one()) * k,
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
            q,
            k,
            delta,
            input,
            output,
            output_aux: Rc::new(output_aux),
            output_mod: Rc::new(output_mod),
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
        6 + self.output_bits.len() + self.offset_aux_bits.len()
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
        res.push(self.output_aux);
        res.push(self.output_mod);
        res.push(self.offset);
        res.push(self.option);
        res.extend(self.output_bits.iter());
        res.extend(self.offset_aux_bits.iter());
        res
    }

    /// Extract DecomposedBitsEval instance
    #[inline]
    pub fn extract_decomposed_bits(&self) -> (BitDecompositionEval<F>, BitDecompositionEval<F>) {
        (
            BitDecompositionEval {
                d_val: self.output_all.to_owned(),
                d_bits: self.output_bits.to_owned(),
            },
            BitDecompositionEval {
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
            <BitDecompositionIOP<F>>::num_coins(&instance.output_bits_info)
                + <BitDecompositionIOP<F>>::num_coins(&instance.offset_bits_info)
                + 5,
        )
    }

    /// return the number of coins used in this IOP
    pub fn num_coins(info: &RoundInstanceInfo<F>) -> usize {
        <BitDecompositionIOP<F>>::num_coins(&info.output_bits_info)
            + <BitDecompositionIOP<F>>::num_coins(&info.offset_bits_info)
            + 5
    }

    /// Prove round
    pub fn prove(instance: &RoundInstance<F>) -> SumcheckKit<F> {
        let mut trans = Transcript::<F>::new();
        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );
        let eq_at_u = Rc::new(gen_identity_evaluations(&u));

        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);
        let randomness = Self::sample_coins(&mut trans, instance);
        Self::prove_as_subprotocol(&randomness, &mut poly, instance, &eq_at_u);

        let (proof, state) =
            MLSumcheck::prove(&mut trans, &poly).expect("fail to prove the sumcheck protocol");

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
        eq_at_u: &Rc<DenseMultilinearExtension<F>>,
    ) {
        let (output_bits_instance, offset_bits_instance) = instance.extract_decomposed_bits();
        let output_bits_r_num = <BitDecompositionIOP<F>>::num_coins(&instance.output_bits_info);
        let offset_bits_r_num = <BitDecompositionIOP<F>>::num_coins(&instance.offset_bits_info);
        assert_eq!(randomness.len(), output_bits_r_num + offset_bits_r_num + 5);
        // 1. add products used to prove decomposition
        BitDecompositionIOP::prepare_products_of_polynomial(
            &randomness[..output_bits_r_num],
            poly,
            &output_bits_instance,
            eq_at_u,
        );
        BitDecompositionIOP::prepare_products_of_polynomial(
            &randomness[output_bits_r_num..output_bits_r_num + offset_bits_r_num],
            poly,
            &offset_bits_instance,
            eq_at_u,
        );

        let lambda_1 = randomness[randomness.len() - 5];
        let lambda_2 = randomness[randomness.len() - 4];
        let r_0 = randomness[randomness.len() - 3];
        let r_1 = randomness[randomness.len() - 2];
        let r_2 = randomness[randomness.len() - 1];
        // add sumcheck for \sum_{x} eq(u, x) * e(x) * (1-e(x))=0
        poly.add_product_with_linear_op(
            [
                Rc::clone(eq_at_u),
                Rc::clone(&instance.output_mod),
                Rc::clone(&instance.output_mod),
            ],
            &[
                (F::one(), F::zero()),
                (F::one(), F::zero()),
                (-F::one(), F::one()),
            ],
            r_0,
        );

        // 2. add sumcheck1 for \sum_{x} eq(u, x) * w(x) * (1-w(x)) = 0, i.e. w(x)\in\{0,1\}^l with random coefficient r_1
        poly.add_product_with_linear_op(
            [
                Rc::clone(eq_at_u),
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

        // 3. add sumcheck2 for \sum_{x} eq(u, x) * [w(x) * ((a(x)-k) * \lambda_1 + b(x) * \lambda_2) +
        //                                           (1 - w(x)) * (a(x) - (2b'(x)-1) * k - c(x))]=0
        // with random coefficient r_2 where \lambda_1 and \lambda_2 are chosen by the verifier

        // The following steps add five products composing the function in the above sumcheck protocol
        // product: eq(u, x) * w(x) * ((a(x)-k) * \lambda_1)
        poly.add_product_with_linear_op(
            [
                Rc::clone(eq_at_u),
                Rc::clone(&instance.option),
                Rc::clone(&instance.input),
            ],
            &[
                (F::one(), F::zero()),
                (F::one(), F::zero()),
                (lambda_1, -lambda_1 * instance.k),
            ],
            r_2,
        );
        // product: eq(u, x) * w(x) * (b(x) * \lambda_2)
        poly.add_product_with_linear_op(
            [
                Rc::clone(eq_at_u),
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
                Rc::clone(eq_at_u),
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
        // product: eq(u, x) * (1 - w(x)) * (- (2b'(x)-1) * k)
        // product: eq(u, x) * (1 - w(x)) * (2k * b'(x) - k) * (-r_2)
        poly.add_product_with_linear_op(
            [
                Rc::clone(eq_at_u),
                Rc::clone(&instance.option),
                Rc::clone(&instance.output_aux),
            ],
            &[
                (F::one(), F::zero()),
                (-F::one(), F::one()),
                ((F::one() + F::one()) * instance.k, -instance.k),
            ],
            -r_2,
        );
        // product: eq(u, x) * (1 - w(x)) * (-c(x))
        poly.add_product_with_linear_op(
            [
                Rc::clone(eq_at_u),
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

        let mut subclaim = MLSumcheck::verify(
            &mut trans,
            &wrapper.info,
            wrapper.claimed_sum,
            &wrapper.proof,
        )
        .expect("fail to verify the sumcheck protocol");
        let eq_at_u_r = eval_identity_function(&u, &subclaim.point);

        if !Self::verify_as_subprotocol(&randomness, &mut subclaim, evals, info, eq_at_u_r) {
            return false;
        }

        subclaim.expected_evaluations == F::zero() && wrapper.claimed_sum == F::zero()
    }

    /// Verify round
    pub fn verify_as_subprotocol(
        randomness: &[F],
        subclaim: &mut SubClaim<F>,
        evals: &RoundInstanceEval<F>,
        info: &RoundInstanceInfo<F>,
        eq_at_u_r: F,
    ) -> bool {
        let (output_bits_evals, offset_bits_evals) = evals.extract_decomposed_bits();
        let output_bits_r_num = <BitDecompositionIOP<F>>::num_coins(&info.output_bits_info);
        let offset_bits_r_num = <BitDecompositionIOP<F>>::num_coins(&info.offset_bits_info);
        assert_eq!(randomness.len(), output_bits_r_num + offset_bits_r_num + 5);
        let check_output_bits = <BitDecompositionIOP<F>>::verify_subclaim(
            &randomness[..output_bits_r_num],
            subclaim,
            &output_bits_evals,
            &info.output_bits_info,
            eq_at_u_r,
        );
        let check_offset_bits = <BitDecompositionIOP<F>>::verify_subclaim(
            &randomness[output_bits_r_num..output_bits_r_num + offset_bits_r_num],
            subclaim,
            &offset_bits_evals,
            &info.offset_bits_info,
            eq_at_u_r,
        );
        if !(check_output_bits && check_offset_bits) {
            return false;
        }
        let lambda_1 = randomness[randomness.len() - 5];
        let lambda_2 = randomness[randomness.len() - 4];
        let r_0 = randomness[randomness.len() - 3];
        let r_1 = randomness[randomness.len() - 2];
        let r_2 = randomness[randomness.len() - 1];

        let f_two = F::one() + F::one();
        // check 2: check the subclaim returned from the sumcheck protocol
        subclaim.expected_evaluations -=
            r_0 * eq_at_u_r * evals.output_mod * (F::one() - evals.output_mod);
        subclaim.expected_evaluations -= r_1 * eq_at_u_r * evals.option * (F::one() - evals.option);
        subclaim.expected_evaluations -= r_2
            * eq_at_u_r
            * (evals.option * ((evals.input - info.k) * lambda_1 + evals.output * lambda_2)
                + (F::one() - evals.option)
                    * (evals.input
                        - (f_two * evals.output_aux - F::one()) * info.k
                        - evals.offset));

        // check 3: b' = b + e * q
        evals.output_aux == evals.output + evals.output_mod * info.q
    }
}

impl<F, EF> RoundSnarks<F, EF>
where
    F: Field + Serialize + for<'de> Deserialize<'de>,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
{
    /// Complied with PCS to get SNARKs
    pub fn snarks<H, C, S>(instance: &RoundInstance<F>, code_spec: &S)
    where
        H: Hash + Sync + Send,
        C: LinearCode<F> + Serialize + for<'de> Deserialize<'de>,
        S: LinearCodeSpec<F, Code = C> + Clone,
    {
        let instance_info = instance.info();
        println!("Prove {instance_info}\n");
        // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
        let committed_poly = instance.generate_oracle();
        // 1. Use PCS to commit the above polynomial.
        let start = Instant::now();
        let pp =
            BrakedownPCS::<F, H, C, S, EF>::setup(committed_poly.num_vars, Some(code_spec.clone()));
        let setup_time = start.elapsed().as_millis();

        let start = Instant::now();
        let (comm, comm_state) = BrakedownPCS::<F, H, C, S, EF>::commit(&pp, &committed_poly);
        let commit_time = start.elapsed().as_millis();

        // 2. Prover generates the proof
        let prover_start = Instant::now();
        let mut iop_proof_size = 0;
        let mut prover_trans = Transcript::<EF>::new();
        // Convert the original instance into an instance defined over EF
        let instance_ef = instance.to_ef::<EF>();
        let instance_info = instance_ef.info();

        // 2.1 Generate the random point to instantiate the sumcheck protocol
        let prover_u = prover_trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );
        let eq_at_u = Rc::new(gen_identity_evaluations(&prover_u));

        // 2.2 Construct the polynomial and the claimed sum to be proved in the sumcheck protocol
        let mut sumcheck_poly = ListOfProductsOfPolynomials::<EF>::new(instance.num_vars);
        let claimed_sum = EF::zero();
        let randomness = RoundIOP::sample_coins(&mut prover_trans, &instance_ef);
        RoundIOP::prove_as_subprotocol(&randomness, &mut sumcheck_poly, &instance_ef, &eq_at_u);

        let poly_info = sumcheck_poly.info();

        // 2.3 Generate proof of sumcheck protocol
        let (sumcheck_proof, sumcheck_state) =
            <MLSumcheck<EF>>::prove(&mut prover_trans, &sumcheck_poly)
                .expect("Proof generated in Addition In Zq");
        iop_proof_size += bincode::serialize(&sumcheck_proof).unwrap().len();
        let iop_prover_time = prover_start.elapsed().as_millis();

        // 2.4 Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol
        let start = Instant::now();
        let evals = instance.evaluate_ext(&sumcheck_state.randomness);

        // 2.5 Reduce the proof of the above evaluations to a single random point over the committed polynomial
        let mut requested_point = sumcheck_state.randomness.clone();
        requested_point.extend(&prover_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            instance.log_num_oracles(),
        ));
        let oracle_eval = committed_poly.evaluate_ext(&requested_point);

        // 2.6 Generate the evaluation proof of the requested point
        let eval_proof = BrakedownPCS::<F, H, C, S, EF>::open(
            &pp,
            &comm,
            &comm_state,
            &requested_point,
            &mut prover_trans,
        );
        let pcs_open_time = start.elapsed().as_millis();

        // 3. Verifier checks the proof
        let verifier_start = Instant::now();
        let mut verifier_trans = Transcript::<EF>::new();

        // 3.1 Generate the random point to instantiate the sumcheck protocol
        let verifier_u = verifier_trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );

        // 3.2 Generate the randomness used to randomize all the sub-sumcheck protocols
        let randomness = verifier_trans.get_vec_challenge(
            b"randomness to combine sumcheck protocols",
            <RoundIOP<EF>>::num_coins(&instance_info),
        );

        // 3.3 Check the proof of the sumcheck protocol
        let mut subclaim = <MLSumcheck<EF>>::verify(
            &mut verifier_trans,
            &poly_info,
            claimed_sum,
            &sumcheck_proof,
        )
        .expect("Verify the sumcheck proof generated in Round");
        let eq_at_u_r = eval_identity_function(&verifier_u, &subclaim.point);

        // 3.4 Check the evaluation over a random point of the polynomial proved in the sumcheck protocol using evaluations over these small oracles used in IOP
        let check_subcliam = RoundIOP::<EF>::verify_as_subprotocol(
            &randomness,
            &mut subclaim,
            &evals,
            &instance_info,
            eq_at_u_r,
        );
        assert!(check_subcliam && subclaim.expected_evaluations == EF::zero());
        let iop_verifier_time = verifier_start.elapsed().as_millis();

        // 3.5 and also check the relation between these small oracles and the committed oracle
        let start = Instant::now();
        let mut pcs_proof_size = 0;
        let flatten_evals = evals.flatten();
        let oracle_randomness = verifier_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            evals.log_num_oracles(),
        );
        let check_oracle = verify_oracle_relation(&flatten_evals, oracle_eval, &oracle_randomness);
        assert!(check_oracle);

        // 3.5 Check the evaluation of a random point over the committed oracle
        let check_pcs = BrakedownPCS::<F, H, C, S, EF>::verify(
            &pp,
            &comm,
            &requested_point,
            oracle_eval,
            &eval_proof,
            &mut verifier_trans,
        );
        assert!(check_pcs);
        let pcs_verifier_time = start.elapsed().as_millis();
        pcs_proof_size += bincode::serialize(&eval_proof).unwrap().len()
            + bincode::serialize(&flatten_evals).unwrap().len();

        // 4. print statistic
        print_statistic(
            iop_prover_time + pcs_open_time,
            iop_verifier_time + pcs_verifier_time,
            iop_proof_size + pcs_proof_size,
            iop_prover_time,
            iop_verifier_time,
            iop_proof_size,
            committed_poly.num_vars,
            instance.num_oracles(),
            instance.num_vars,
            setup_time,
            commit_time,
            pcs_open_time,
            pcs_verifier_time,
            pcs_proof_size,
        );
    }
}
