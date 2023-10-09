use std::ops::Mul;

use num_traits::{Inv, One};

use crate::algebra::{MulAssociativity, MulCommutativity};

pub trait MultiplicativeMagma: Sized + Mul<Self, Output = Self> {}

impl<G> MultiplicativeMagma for G where G: Sized + Mul<Self, Output = Self> {}

pub trait MultiplicativeSemiGroup: MultiplicativeMagma + MulAssociativity {}

impl<G> MultiplicativeSemiGroup for G where G: MultiplicativeMagma + MulAssociativity {}

pub trait MultiplicativeMonoid: MultiplicativeSemiGroup + One {}

impl<G> MultiplicativeMonoid for G where G: MultiplicativeSemiGroup + One {}

pub trait MultiplicativeGroup: MultiplicativeMonoid + Inv<Output = Self> {}

impl<G> MultiplicativeGroup for G where G: MultiplicativeMonoid + Inv<Output = Self> {}

pub trait MultiplicativeAbelianGroup: MultiplicativeGroup + MulCommutativity {}

impl<G> MultiplicativeAbelianGroup for G where G: MultiplicativeGroup + MulCommutativity {}
