use std::marker::PhantomData;

use rand::SeedableRng;
use rand_distr::Distribution;
use serde::Serialize;

use crate::{Field, FieldUniformSampler};

use super::{Block, Prg};

/// A transcript consists of a Merlin transcript and a `sampler``
/// to sample uniform field elements.
pub struct Transcript<F: Field> {
    transcript: merlin::Transcript,
    sampler: FieldUniformSampler<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> Transcript<F> {
    /// Create a new IOP transcript.
    #[inline]
    pub fn new() -> Self {
        Self {
            transcript: merlin::Transcript::new(b""),
            sampler: FieldUniformSampler::new(),
            _marker: PhantomData,
        }
    }
}
impl<F: Field + Serialize> Transcript<F> {
    /// Append the message to the transcript.
    #[inline]
    pub fn append_message(&mut self, msg: &[u8]) {
        self.transcript.append_message(b"", msg);
    }

    /// Append elements to the transcript.
    #[inline]
    pub fn append_elements(&mut self, elems: &[F]) {
        self.append_message(&bincode::serialize(elems).unwrap());
    }

    /// Generate the challenge bytes from the current transcript
    #[inline]
    pub fn get_challenge_bytes(&mut self, bytes: &mut [u8]) {
        self.transcript.challenge_bytes(b"", bytes);
    }

    /// Generate the challenge from the current transcript
    /// and append it to the transcript.
    pub fn get_and_append_challenge(&mut self) -> F {
        let mut seed = [0u8; 16];
        self.transcript.challenge_bytes(b"", &mut seed);
        let mut prg = Prg::from_seed(Block::from(seed));
        let challenge: F = self.sampler.sample(&mut prg);
        self.append_message(&bincode::serialize(&challenge).unwrap());

        challenge
    }

    /// Generate the challenge vector from the current transcript
    /// and append it to the transcript.
    pub fn get_vec_and_append_challenge(&mut self, num: usize) -> Vec<F> {
        let mut seed = [0u8; 16];
        self.transcript.challenge_bytes(b"", &mut seed);
        let mut prg = Prg::from_seed(Block::from(seed));

        let challenge = self.sampler.sample_iter(&mut prg).take(num).collect();
        self.append_message(&bincode::serialize(&challenge).unwrap());

        challenge
    }
}

impl<F: Field> Default for Transcript<F> {
    fn default() -> Self {
        Self::new()
    }
}
