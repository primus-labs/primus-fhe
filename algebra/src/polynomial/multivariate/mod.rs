mod data_structures;
mod multilinear;

pub use data_structures::{ListOfProductsOfPolynomials, PolynomialInfo};
pub use multilinear::UF;
pub use multilinear::{
    DenseMultilinearExtension, DenseMultilinearExtensionBase, MultilinearExtension,
    MultilinearExtensionBase, SparsePolynomial,
};
