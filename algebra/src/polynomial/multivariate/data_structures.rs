// It is derived from https://github.com/arkworks-rs/sumcheck/blob/master/src/ml_sumcheck/data_structures.rs .

use std::{collections::HashMap, rc::Rc};

use crate::Field;

use super::{DenseMultilinearExtension, MultilinearExtension};

/// Stores a list of products of `DenseMultilinearExtension` that is meant to be added together.
///
/// The polynomial is represented by a list of products of polynomials along with its coefficient that is meant to be added together.
///
/// This data structure of the polynomial is a list of list of `(coefficient, DenseMultilinearExtension)`.
/// * Number of products n = `self.products.len()`,
/// * Number of multiplicands of ith product m_i = `self.products[i].1.len()`,
/// * Coefficient of i-th product c_i = `self.products[i].0`
///
/// The resulting polynomial is
///
/// $$\sum_{i=0}^{n}c_i\cdot\prod_{j=0}^{m_i}P_{ij}$$
///
/// The resulting polynomial is used as the prover key.
#[derive(Clone)]
pub struct ListOfProductsOfPolynomials<F: Field> {
    /// max number of multiplicands in each product
    pub max_multiplicands: usize,
    /// number of variables of the polynomial
    pub num_variables: usize,
    /// list of reference to products (as usize) of multilinear extension
    /// (index, (a, b)) where `index` indicates the location of MLE and
    /// (a: F, b: F) can used to wrap a linear operation over the original MLE f, i.e. a \cdot f + b
    #[allow(clippy::type_complexity)]
    pub products: Vec<(F, Vec<(usize, (F, F))>)>,
    /// Stores multilinear extensions in which product multiplicand can refer to.
    pub flattened_ml_extensions: Vec<Rc<DenseMultilinearExtension<F>>>,
    raw_pointers_lookup_table: HashMap<*const DenseMultilinearExtension<F>, usize>,
}

/// Extract the max number of multiplicands and number of variables of the list of products.
impl<F: Field> ListOfProductsOfPolynomials<F> {
    /// Extract the max number of multiplicands and number of variables of the list of products.
    #[inline]
    pub fn info(&self) -> PolynomialInfo {
        PolynomialInfo {
            max_multiplicands: self.max_multiplicands,
            num_variables: self.num_variables,
        }
    }
}

#[derive(Clone, Copy)]
/// Stores the number of variables and max number of multiplicands of the added polynomial used by the prover.
/// This data structures will be used as the verifier key.
pub struct PolynomialInfo {
    /// max number of multiplicands in each product
    pub max_multiplicands: usize,
    /// number of variables of the polynomial
    pub num_variables: usize,
}

impl<F: Field> ListOfProductsOfPolynomials<F> {
    /// Returns an empty polynomial
    #[inline]
    pub fn new(num_variables: usize) -> Self {
        ListOfProductsOfPolynomials {
            max_multiplicands: 0,
            num_variables,
            products: Vec::new(),
            flattened_ml_extensions: Vec::new(),
            raw_pointers_lookup_table: HashMap::new(),
        }
    }

    /// Add a list of multilinear extensions that is meant to be multiplied together.
    /// Here we wrap a linear operation on the same MLE so that we can add the
    /// product like f(x) \cdot (2f(x) + 3) \cdot (4f(x) + 4) with only one Rc.
    /// The resulting polynomial will be multiplied by the scalar `coefficient`.
    pub fn add_product_with_linear_op(
        &mut self,
        product: impl IntoIterator<Item = Rc<DenseMultilinearExtension<F>>>,
        op_coefficient: &[(F, F)],
        coefficient: F,
    ) {
        let product: Vec<Rc<DenseMultilinearExtension<F>>> = product.into_iter().collect();
        self.max_multiplicands = self.max_multiplicands.max(product.len());
        assert_eq!(product.len(), op_coefficient.len());
        assert!(!product.is_empty());
        let mut indexed_product_with_op: Vec<(usize, (F, F))> =
            Vec::with_capacity(op_coefficient.len());

        // (a, b) is the linear operation perfomed on the original MLE pointed by m
        for (m, (a, b)) in product.iter().zip(op_coefficient) {
            assert_eq!(
                m.num_vars, self.num_variables,
                "product has a multiplicand with wrong number of variables"
            );
            let m_ptr: *const DenseMultilinearExtension<F> = Rc::as_ptr(m);
            if let Some(index) = self.raw_pointers_lookup_table.get(&m_ptr) {
                indexed_product_with_op.push((*index, (*a, *b)));
            } else {
                let curr_index = self.flattened_ml_extensions.len();
                self.flattened_ml_extensions.push(m.clone());
                self.raw_pointers_lookup_table.insert(m_ptr, curr_index);
                indexed_product_with_op.push((curr_index, (*a, *b)));
            }
        }
        self.products.push((coefficient, indexed_product_with_op));
    }

    /// Standard add_product in the sumcheck
    /// Add a list of multilinear extensions that is meant to be multiplied together.
    /// The resulting polynomial will be multiplied by the scalar `coefficient`.
    pub fn add_product(
        &mut self,
        product: impl IntoIterator<Item = Rc<DenseMultilinearExtension<F>>>,
        coefficient: F,
    ) {
        let product: Vec<Rc<DenseMultilinearExtension<F>>> = product.into_iter().collect();
        let mut op_coefficient: Vec<(F, F)> = Vec::with_capacity(product.len());
        for _ in 0..product.len() {
            op_coefficient.push((F::ONE, F::ZERO));
        }
        self.add_product_with_linear_op(product, &op_coefficient, coefficient);
    }

    /// Evaluate the polynomial at point `point`
    pub fn evaluate(&self, point: &[F]) -> F {
        self.products.iter().fold(F::ZERO, |result, (c, p)| {
            result
                + p.iter().fold(*c, |acc, &i| {
                    // acc * (f(point) * a + b)
                    acc * (self.flattened_ml_extensions[i.0].evaluate(point) * i.1 .0 + i.1 .1)
                })
        })
    }
}
