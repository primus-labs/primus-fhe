use std::ops::{Add, Neg};

use num_traits::Zero;

use crate::algebra::{AddAssociativity, AddCommutativity};

/// Additive magma only needs to satisfy the closure
pub trait AdditiveMagma: Sized + Add<Self, Output = Self> {}

impl<G> AdditiveMagma for G where G: Sized + Add<Self, Output = Self> {}

pub trait AdditiveSemiGroup: AdditiveMagma + AddAssociativity {}

impl<G> AdditiveSemiGroup for G where G: AdditiveMagma + AddAssociativity {}

pub trait AdditiveMonoid: AdditiveSemiGroup + Zero {}

impl<G> AdditiveMonoid for G where G: AdditiveSemiGroup + Zero {}

pub trait AdditiveGroup: AdditiveMonoid + Neg<Output = Self> {}

impl<G> AdditiveGroup for G where G: AdditiveMonoid + Neg<Output = Self> {}

pub trait AdditiveAbelianGroup: AdditiveGroup + AddCommutativity {}

impl<G> AdditiveAbelianGroup for G where G: AdditiveGroup + AddCommutativity {}
