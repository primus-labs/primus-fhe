//! utility

use std::sync::{Arc, Mutex};

/// NOT
#[inline]
pub const fn not(a: bool) -> bool {
    !a
}

/// AND
#[inline]
pub const fn and(a: bool, b: bool) -> bool {
    a & b
}

/// NAND
#[inline]
pub const fn nand(a: bool, b: bool) -> bool {
    not(and(a, b))
}

/// OR
#[inline]
pub const fn or(a: bool, b: bool) -> bool {
    a | b
}

/// NOR
#[inline]
pub const fn nor(a: bool, b: bool) -> bool {
    not(or(a, b))
}

/// XOR
#[inline]
pub const fn xor(a: bool, b: bool) -> bool {
    a ^ b
}

/// XNOR
#[inline]
pub const fn xnor(a: bool, b: bool) -> bool {
    not(xor(a, b))
}

/// MAJ
#[inline]
pub const fn majority(a: bool, b: bool, c: bool) -> bool {
    (a & b) | (b & c) | (a & c)
}

pub struct Pool<T>(Arc<Mutex<Vec<T>>>);

impl<T> Default for Pool<T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for Pool<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> Pool<T> {
    #[inline]
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    #[inline]
    pub fn get(&self) -> Option<T> {
        let mut data = self.0.lock().unwrap();
        data.pop()
    }

    #[inline]
    pub fn store(&self, value: T) {
        let mut data = self.0.lock().unwrap();
        data.push(value);
    }

    #[inline]
    pub fn clear(&self) {
        let mut data = self.0.lock().unwrap();
        data.clear();
    }
}
