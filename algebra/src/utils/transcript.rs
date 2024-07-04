use std::marker::PhantomData;

use merlin::Transcript;
use rand::SeedableRng;
use rand_distr::Distribution;
use serde::Serialize;

use crate::{Field, FieldUniformSampler};

use super::{Block, Prg};

/// An IOP transcript consists of a Merlin transcript and a `sampler``
/// to sample uniform field elements.
pub struct IOPTranscript<F: Field> {
    transcript: Transcript,
    sampler: FieldUniformSampler<F>,
    _marker: PhantomData<F>,
}

impl<F: Field + Serialize> IOPTranscript<F> {
    /// Create a new IOP transcript.
    pub fn new() -> Self {
        Self {
            transcript: Transcript::new(b""),
            sampler: FieldUniformSampler::new(),
            _marker: PhantomData,
        }
    }

    /// Append the message to the transcript.
    pub fn append_message(&mut self, msg: &[u8]) {
        self.transcript.append_message(b"", msg);
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
}

impl<F: Field> Default for IOPTranscript<F> {
    fn default() -> Self {
        Self::new()
    }
}
