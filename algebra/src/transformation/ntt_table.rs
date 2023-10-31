use crate::field::prime_fields::MulFactor;

/// This struct store the pre-computed data for number theory transform and
/// inverse number theory transform.
///
/// ## The structure members meet the following conditions:
///
/// 1. `coeff_count` = 1 << `coeff_count_power`
/// 1. `root` ^ `2 * coeff_count` = -1 mod `modulus`
/// 1. `root` * `inv_root` = 1 mod `modulus`
/// 1. `coeff_count` * `inv_degree_modulo` = 1 mod `modulus`
/// 1. `root_powers` holds 1~(n-1)-th powers of root in bit-reversed order, the 0-th power is left unset.
/// 1. `inv_root_powers` holds 1~(n-1)-th powers of inverse root in scrambled order, the 0-th power is left unset.
///
/// ## Compare three orders:
///
/// ```plain
/// normal order:        0  1  2  3  4  5  6  7
///
/// bit-reversed order:  0  4  2  6  1  5  3  7
///                         -  ----  ----------
/// scrambled order:     0  1  5  3  7  2  6  4
///                         ----------  ----  -
/// ```
pub struct NTTTable<F> {
    root: F,
    inv_root: F,
    coeff_count_power: u32,
    coeff_count: usize,
    inv_degree: MulFactor<F>,
    root_powers: Vec<MulFactor<F>>,
    inv_root_powers: Vec<MulFactor<F>>,
}

impl<F> NTTTable<F> {
    /// Creates a new [`NTTTable<F>`].
    pub fn new(
        root: F,
        inv_root: F,
        coeff_count_power: u32,
        coeff_count: usize,
        inv_degree: MulFactor<F>,
        root_powers: Vec<MulFactor<F>>,
        inv_root_powers: Vec<MulFactor<F>>,
    ) -> Self {
        Self {
            root,
            inv_root,
            coeff_count_power,
            coeff_count,
            inv_degree,
            root_powers,
            inv_root_powers,
        }
    }

    /// Returns a reference to the root of this [`NTTTable<F>`].
    pub fn root(&self) -> &F {
        &self.root
    }

    /// Returns a reference to the inv root of this [`NTTTable<F>`].
    pub fn inv_root(&self) -> &F {
        &self.inv_root
    }

    /// Returns the coeff count power of this [`NTTTable<F>`].
    pub fn coeff_count_power(&self) -> u32 {
        self.coeff_count_power
    }

    /// Returns the coeff count of this [`NTTTable<F>`].
    pub fn coeff_count(&self) -> usize {
        self.coeff_count
    }

    /// Returns a reference to the inv degree of this [`NTTTable<F>`].
    pub fn inv_degree(&self) -> &MulFactor<F> {
        &self.inv_degree
    }

    /// Returns a reference to the root powers of this [`NTTTable<F>`].
    pub fn root_powers(&self) -> &[MulFactor<F>] {
        self.root_powers.as_ref()
    }

    /// Returns a reference to the inv root powers of this [`NTTTable<F>`].
    pub fn inv_root_powers(&self) -> &[MulFactor<F>] {
        self.inv_root_powers.as_ref()
    }
}
