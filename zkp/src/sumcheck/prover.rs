//! Prover for multilinear sumcheck protocol
// It is derived from https://github.com/arkworks-rs/sumcheck/blob/master/src/ml_sumcheck/protocol/prover.rs.

use core::panic;
use std::vec;

use algebra::Field;
use algebra::{DenseMultilinearExtension, ListOfProductsOfPolynomials, MultilinearExtension};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use serde::{Deserialize, Serialize};

use super::verifier::VerifierMsg;
use super::IPForMLSumcheck;

/// Prover Message
#[derive(Clone, Serialize, Deserialize)]
pub struct ProverMsg<F: Field> {
    /// evaluations on P(0), P(1), P(2), ...
    pub(crate) evaluations: Vec<F>,
}

/// Prover State
pub struct ProverState<F: Field> {
    /// sampled randomness given by the verifier
    pub randomness: Vec<F>,
    /// Stores the list of products that is meant to be added together.
    /// Each multiplicand is represented by the index in flattened_ml_extensions
    pub list_of_products: Vec<(F, Vec<usize>)>,
    /// Stores the linear operations, each of which is successively (in the same order) performed over the each MLE of each product stored in the above `products`
    /// so each (a: F, b: F) can used to wrap a linear operation over the original MLE f, i.e. a \cdot f + b
    pub linear_ops: Vec<Vec<(F, F)>>,
    /// Stores a list of multilinear extensions in which `self.list_of_products` point to
    pub flattened_ml_extensions: Vec<DenseMultilinearExtension<F>>,
    /// Number of variables
    pub num_vars: usize,
    /// Max number of multiplicands in a product
    pub max_multiplicands: usize,
    /// The current round number
    pub round: usize,
}

impl<F: Field> IPForMLSumcheck<F> {
    /// Initilaize the prover to argue for the sum of polynomial over {0, 1}^`num_vars`
    ///
    /// The polynomial is represented by a list of products of polynomials along with its coefficient that is meant to be added together.
    ///
    /// This data structure of the polynomial is a list of list of `(coefficient, DenseMultilinearExtension`.
    /// * Number of products n = `polynomial.products.len()`,
    /// * Number of multiplicands of i-th product m_i = `polynomial.products[i].1.len`,
    /// * Coefficient of i-th product c_i = `polynomial.products[i].0`
    ///
    /// The resulting polynomial is
    ///
    /// $$\sum_{i=0}^{n} c_i \cdot \prod_{j=0}^{m_i}P_{ij}$$
    pub fn prover_init(polynomial: &ListOfProductsOfPolynomials<F>) -> ProverState<F> {
        if polynomial.num_variables == 0 {
            panic!("Attempt to prove a constant.")
        }

        // create a deep copy of all unique MLExtensions
        let flattened_ml_extensions = polynomial
            .flattened_ml_extensions
            .iter()
            .map(|x| x.as_ref().clone())
            .collect();

        ProverState {
            randomness: Vec::with_capacity(polynomial.num_variables),
            list_of_products: polynomial.products.clone(),
            linear_ops: polynomial.linear_ops.clone(),
            flattened_ml_extensions,
            num_vars: polynomial.num_variables,
            max_multiplicands: polynomial.max_multiplicands,
            round: 0,
        }
    }

    /// Receive message from the verifier, generate prover messages, and proceed to the next round.
    ///
    /// Main algorithm used is from section 3.2 of [XZZPS19](https://eprint.iacr.org/2019/317.pdf#subsection.3.2).
    pub fn prove_round(
        prover_state: &mut ProverState<F>,
        v_msg: &Option<VerifierMsg<F>>,
    ) -> ProverMsg<F> {
        if let Some(msg) = v_msg {
            if prover_state.round == 0 {
                panic!("First round should be prover first.")
            }
            prover_state.randomness.push(msg.randomness);

            // fix argument
            let i = prover_state.round;
            let r = prover_state.randomness[i - 1];
            prover_state
                .flattened_ml_extensions
                .par_iter_mut()
                .for_each(|mulplicand| {
                    *mulplicand = mulplicand.fix_variables(&[r]);
                });
        } else if prover_state.round > 0 {
            panic!("Verifier message is empty")
        }

        prover_state.round += 1;

        if prover_state.round > prover_state.num_vars {
            panic!("Prover is not active");
        }

        let i = prover_state.round;
        let nv = prover_state.num_vars;
        // the degree of univariate polynomial sent by prover at this round
        let degree = prover_state.max_multiplicands;

        // In effect, this loop is essentially doing simply:
        // for b in 0..1 << (nv - i)
        // The goal is to evaluate degree + 1 points for each b, all of which has been fixed with the same (i-1) variables.
        // Note that the function proved in the sumcheck is a sum of products.
        let res = prover_state
            .list_of_products
            .par_iter()
            .zip(prover_state.linear_ops.par_iter())
            .map(|((coefficient, products), linear_ops)| {
                let mut products_sum = vec![F::zero(); degree + 1];
                for b in 0..1 << (nv - i) {
                    let mut product = vec![*coefficient; degree + 1];
                    // This loop is evaluating each MLE to update the product via performing the accumulated multiplication.
                    for (&jth_product, &(op_a, op_b)) in products.iter().zip(linear_ops.iter()) {
                        // (a, b) is a wrapped linear operation over original MLE
                        let table = &prover_state.flattened_ml_extensions[jth_product];
                        let op = table[b << 1] * op_a;
                        let mut start = op + op_b;
                        let step = (table[(b << 1) + 1] * op_a) - op;
                        // Evaluate each point P(t) for t = 0..degree + 1 via the accumulated addition instead of the multiplication by t.
                        // [t|b] = [0|b] + t * ([1|b] - [0|b]) represented by little-endian
                        for p in product.iter_mut() {
                            *p *= start;
                            start += step;
                        }
                    }
                    for t in 0..degree + 1 {
                        products_sum[t] += product[t];
                    }
                }
                products_sum
            })
            .reduce(
                || vec![F::zero(); degree + 1],
                |acc, a| acc.iter().zip(a.iter()).map(|(&acc, &a)| acc + a).collect(),
            );
        ProverMsg { evaluations: res }
    }
}
