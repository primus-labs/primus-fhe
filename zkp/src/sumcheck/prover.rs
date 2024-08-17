//! Prover for multilinear sumcheck protocol
// It is derived from https://github.com/arkworks-rs/sumcheck/blob/master/src/ml_sumcheck/protocol/prover.rs.

use core::panic;
use std::marker::PhantomData;
use std::vec;

use algebra::{AbstractExtensionField, Field, UF};
use algebra::{DenseMultilinearExtension, ListOfProductsOfPolynomials, MultilinearExtension};
use serde::ser::SerializeSeq;
use serde::Serialize;

use super::verifier::VerifierMsg;
use super::IPForMLSumcheck;
use std::rc::Rc;

/// Prover Message
#[derive(Clone)]
pub struct ProverMsg<F: Field, EF: AbstractExtensionField<F>> {
    /// evaluations on P(0), P(1), P(2), ...
    pub(crate) evaluations: Rc<Vec<EF>>,
    _marker: PhantomData<F>,
}

impl<F: Field, EF: AbstractExtensionField<F>> Serialize for ProverMsg<F, EF> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.evaluations.len()))?;
        for e in self.evaluations.iter() {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}

/// Prover State
pub struct ProverState<F: Field, EF: AbstractExtensionField<F>> {
    /// sampled randomness given by the verifier
    pub randomness: Vec<EF>,
    /// Stores the list of products that is meant to be added together.
    /// Each multiplicand is represented by the index in flattened_ml_extensions
    pub list_of_products: Vec<(EF, Vec<usize>)>,
    /// Stores the linear operations, each of which is successively (in the same order) perfomed over the each MLE of each product stored in the above `products`
    /// so each (a: F, b: F) can used to wrap a linear operation over the original MLE f, i.e. a \cdot f + b
    #[allow(clippy::type_complexity)]
    pub linear_ops: Vec<Vec<(UF<F, EF>, UF<F, EF>)>>,
    /// Stores a list of multilinear extensions in which `self.list_of_products` point to
    pub flattened_ml_extensions: Vec<DenseMultilinearExtension<F, EF>>,
    /// Number of variables
    pub num_vars: usize,
    /// Max number of multiplicands in a product
    pub max_multiplicands: usize,
    /// The current round number
    pub round: usize,
}

impl<F: Field, EF: AbstractExtensionField<F>> IPForMLSumcheck<F, EF> {
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
    pub fn prover_init(polynomial: &ListOfProductsOfPolynomials<F, EF>) -> ProverState<F, EF> {
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
        prover_state: &mut ProverState<F, EF>,
        v_msg: &Option<VerifierMsg<F, EF>>,
    ) -> ProverMsg<F, EF> {
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
                .iter_mut()
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

        let zeros = (vec![EF::zero(); degree + 1], vec![EF::zero(); degree + 1]);
        // In effect, this fold is essentially doing simply:
        // for b in 0..1 << (nv - i)
        // The goal is to evaluate degree + 1 points for each b, all of which has been fixed with the same (i-1) variables.
        // Note that the function proved in the sumcheck is a sum of products.
        let fold_result = (0..1 << (nv - i)).fold(zeros, |(mut products_sum, mut product), b| {
            // This loop is evaluating each product over the specific degree + 1 points.
            for ((coefficient, products), linear_ops) in prover_state
                .list_of_products
                .iter()
                .zip(prover_state.linear_ops.iter())
            {
                product.fill(*coefficient);
                // This loop is evaluating each MLE to update the product via performing the accumulated multiplication.
                for (&jth_product, &(op_a, op_b)) in products.iter().zip(linear_ops.iter()) {
                    // (a, b) is a wrapped linear operation over original MLE
                    let table = &prover_state.flattened_ml_extensions[jth_product];
                    // Reordering the operation is to handle the operation between UF<F, EF> and EF
                    let mut start = op_b + (op_a * table[b << 1]);
                    let step = op_b + (op_a * table[(b << 1) + 1]) - start;
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
            (products_sum, product)
        });
        let products_sum = fold_result.0;

        ProverMsg {
            evaluations: Rc::new(products_sum),
            _marker: PhantomData,
        }
    }
}
