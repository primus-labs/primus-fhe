use std::marker::PhantomData;

use rand::SeedableRng;
use serde::Serialize;

use crate::Field;

use super::{Block, Prg};

/// A transcript consists of a Merlin transcript and a `sampler``
/// to sample uniform field elements.
pub struct Transcript<F: Field> {
    transcript: merlin::Transcript,
    _marker: PhantomData<F>,
}

impl<F: Field> Transcript<F> {
    /// Create a new IOP transcript.
    #[inline]
    pub fn new() -> Self {
        Self {
            transcript: merlin::Transcript::new(b""),
            _marker: PhantomData,
        }
    }
}

impl<F: Field> Transcript<F> {
    /// Append the message to the transcript.
    pub fn append_message<M: Serialize>(&mut self, label: &'static [u8], msg: &M) {
        self.transcript
            .append_message(label, &bincode::serialize(msg).unwrap());
    }

    /// Generate the challenge bytes from the current transcript
    #[inline]
    pub fn get_challenge_bytes(&mut self, label: &'static [u8], bytes: &mut [u8]) {
        self.transcript.challenge_bytes(label, bytes);
    }

    /// Generate the challenge from the current transcript
    pub fn get_challenge(&mut self, label: &'static [u8]) -> F {
        let mut seed = [0u8; 16];
        self.transcript.challenge_bytes(label, &mut seed);
        let mut prg = Prg::from_seed(Block::from(seed));
        F::random(&mut prg)
    }

    /// Generate the challenge vector from the current transcript
    pub fn get_vec_challenge(&mut self, label: &'static [u8], num: usize) -> Vec<F> {
        let mut seed = [0u8; 16];
        self.transcript.challenge_bytes(label, &mut seed);
        let mut prg = Prg::from_seed(Block::from(seed));
        (0..num).map(|_| F::random(&mut prg)).collect()
    }
}

impl<F: Field> Default for Transcript<F> {
    fn default() -> Self {
        Self::new()
    }
}
