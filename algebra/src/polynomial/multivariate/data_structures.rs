// It is derived from https://github.com/arkworks-rs/sumcheck/blob/master/src/ml_sumcheck/data_structures.rs .

use std::{collections::HashMap, marker::PhantomData, rc::Rc};

use serde::Serialize;

use crate::{AbstractExtensionField, Field};

use super::{multilinear::UF, DenseMultilinearExtension, MultilinearExtension};

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
pub struct ListOfProductsOfPolynomials<F: Field, EF: AbstractExtensionField<F>> {
    /// max number of multiplicands in each product
    pub max_multiplicands: usize,
    /// number of variables of the polynomial
    pub num_variables: usize,
    /// list of reference to products (as usize) of multilinear extension
    pub products: Vec<(EF, Vec<usize>)>,
    /// Stores the linear operations, each of which is successively (in the same order) perfomed over the each MLE of each product stored in the above `products`
    /// so each (a: F, b: F) can used to wrap a linear operation over the original MLE f, i.e. a \cdot f + b
    #[allow(clippy::type_complexity)]
    pub linear_ops: Vec<Vec<(UF<F, EF>, UF<F, EF>)>>,
    /// Stores multilinear extensions in which product multiplicand can refer to.
    pub flattened_ml_extensions: Vec<Rc<DenseMultilinearExtension<F, EF>>>,
    raw_pointers_lookup_table: HashMap<*const DenseMultilinearExtension<F, EF>, usize>,
    _marker: PhantomData<F>,
}

/// Extract the max number of multiplicands and number of variables of the list of products.
impl<F: Field, EF: AbstractExtensionField<F>> ListOfProductsOfPolynomials<F, EF> {
    /// Extract the max number of multiplicands and number of variables of the list of products.
    #[inline]
    pub fn info(&self) -> PolynomialInfo {
        PolynomialInfo {
            max_multiplicands: self.max_multiplicands,
            num_variables: self.num_variables,
        }
    }
}

#[derive(Clone, Copy, Serialize)]
/// Stores the number of variables and max number of multiplicands of the added polynomial used by the prover.
/// This data structures will be used as the verifier key.
pub struct PolynomialInfo {
    /// max number of multiplicands in each product
    pub max_multiplicands: usize,
    /// number of variables of the polynomial
    pub num_variables: usize,
}

impl<F: Field, EF: AbstractExtensionField<F>> ListOfProductsOfPolynomials<F, EF> {
    /// Returns an empty polynomial
    #[inline]
    pub fn new(num_variables: usize) -> Self {
        ListOfProductsOfPolynomials {
            max_multiplicands: 0,
            num_variables,
            products: Vec::new(),
            linear_ops: Vec::new(),
            flattened_ml_extensions: Vec::new(),
            raw_pointers_lookup_table: HashMap::new(),
            _marker: PhantomData,
        }
    }

    /// Add a list of multilinear extensions that is meant to be multiplied together.
    /// Here we wrap a linear operation on the same MLE so that we can add the
    /// product like f(x) \cdot (2f(x) + 3) \cdot (4f(x) + 4) with only one Rc.
    /// The resulting polynomial will be multiplied by the scalar `coefficient`.
    #[allow(clippy::type_complexity)]
    pub fn add_product_with_linear_op(
        &mut self,
        product: impl IntoIterator<Item = Rc<DenseMultilinearExtension<F, EF>>>,
        op_coefficient: &[(UF<F, EF>, UF<F, EF>)],
        coefficient: EF,
    ) {
        let product: Vec<Rc<DenseMultilinearExtension<F, EF>>> = product.into_iter().collect();
        self.max_multiplicands = self.max_multiplicands.max(product.len());
        assert_eq!(product.len(), op_coefficient.len());
        assert_eq!(product.len(), op_coefficient.len());
        assert!(!product.is_empty());
        let mut indexed_product: Vec<usize> = Vec::with_capacity(op_coefficient.len());
        let mut linear_ops = Vec::with_capacity(op_coefficient.len());

        // (a, b) is the linear operation perfomed on the original MLE pointed by m
        for (m, (a, b)) in product.iter().zip(op_coefficient) {
            assert_eq!(
                m.num_vars, self.num_variables,
                "product has a multiplicand with wrong number of variables"
            );
            let m_ptr: *const DenseMultilinearExtension<F, EF> = Rc::as_ptr(m);
            if let Some(index) = self.raw_pointers_lookup_table.get(&m_ptr) {
                indexed_product.push(*index);
                linear_ops.push((*a, *b));
            } else {
                let curr_index = self.flattened_ml_extensions.len();
                self.flattened_ml_extensions.push(m.clone());
                self.raw_pointers_lookup_table.insert(m_ptr, curr_index);
                indexed_product.push(curr_index);
                linear_ops.push((*a, *b));
            }
        }
        self.products.push((coefficient, indexed_product));
        self.linear_ops.push(linear_ops);
    }

    /// Standard add_product in the sumcheck
    /// Add a list of multilinear extensions that is meant to be multiplied together.
    /// The resulting polynomial will be multiplied by the scalar `coefficient`.
    #[inline]
    pub fn add_product(
        &mut self,
        product: impl IntoIterator<Item = Rc<DenseMultilinearExtension<F, EF>>>,
        coefficient: EF,
    ) {
        let product: Vec<Rc<DenseMultilinearExtension<F, EF>>> = product.into_iter().collect();
        let mut linear_ops: Vec<(UF<F, EF>, UF<F, EF>)> = Vec::with_capacity(product.len());
        for _ in 0..product.len() {
            linear_ops.push((UF::BaseField(F::one()), UF::BaseField(F::zero())));
        }
        self.add_product_with_linear_op(product, &linear_ops, coefficient);
    }

    /// Evaluate the polynomial at point `point`
    pub fn evaluate(&self, point: &[EF]) -> EF {
        self.products.iter().zip(self.linear_ops.iter()).fold(
            EF::zero(),
            |result, ((c, p), ops)| {
                result
                    + p.iter().zip(ops.iter()).fold(*c, |acc, (i, &(a, b))| {
                        acc * (b + a * self.flattened_ml_extensions[*i].evaluate(point))
                    })
            },
        )
    }
}
