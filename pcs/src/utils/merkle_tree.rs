use serde::{Deserialize, Serialize};

use crate::utils::hash::Hash;
use bincode::Result;
use rayon::prelude::*;

/// Root of the Merkle Tree
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MerkleRoot<H: Hash> {
    /// The depth of the merkle tree
    pub depth: usize,
    /// The root of the merkle tree
    pub root: H::Output,
}

impl<H: Hash> MerkleRoot<H> {
    /// Instantiate a merkle root
    pub fn new(depth: usize, root: H::Output) -> Self {
        Self { depth, root }
    }

    /// Convert into bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self)
    }

    /// Recover from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
    }
}

/// Merkle Tree for Vector Commitment
#[derive(Debug, Clone, Default)]
pub struct MerkleTree<H: Hash + Send + Sync> {
    /// the depth of the merkle tree
    pub depth: usize,
    /// the root of the merkle tree
    pub root: H::Output,
    /// the merkle tree
    pub tree: Vec<H::Output>,
    /// input size,
    pub input_size: usize,
}

impl<H: Hash + Send + Sync> MerkleTree<H> {
    /// Create a new instance.
    pub fn new() -> Self {
        Self {
            depth: 0,
            root: H::Output::default(),
            tree: Vec::default(),
            input_size: 0,
        }
    }

    /// Instantiate a merkle tree by committing the leaves
    /// In this case, we assume all the input leaves as the hashed values.
    ///
    /// # Arguments.
    ///
    /// * `leaves` - The leaves used to generate the merkle tree.
    pub fn generate(&mut self, leaves: &[H::Output]) {
        // Resize the size from leaves size to tree size
        self.input_size = leaves.len();
        let depth = leaves.len().next_power_of_two().ilog2() as usize;
        let size = (1 << (depth + 1)) - 1;
        self.tree = vec![H::Output::default(); size];
        self.tree[..leaves.len()].copy_from_slice(leaves);

        // Use base to index the start of the lower layer
        let mut base = 0;
        for depth in (1..=depth).rev() {
            // View the lower layer as the input and the upper layer as its output
            let input_len = 1 << depth;
            let output_len = input_len >> 1;
            let (inputs, outputs) =
                self.tree[base..base + input_len + output_len].split_at_mut(input_len);

            // Compute the output of the hash function given the input
            inputs
                .par_chunks_exact(2)
                .zip(outputs.par_iter_mut())
                .for_each(|(input, output)| {
                    let mut hasher = H::new();
                    hasher.update_hash_value(input[0].as_ref());
                    hasher.update_hash_value(input[1].as_ref());
                    *output = hasher.output_reset();
                });
            base += input_len;
        }

        self.depth = depth;
        self.root = self.tree[size - 1];
    }

    /// Return merkle paths of the indexed leaf
    /// which consists of the leaf hash and neighbour hashes
    #[inline]
    pub fn query(&self, leaf_idx: usize) -> Vec<H::Output> {
        assert!(leaf_idx <= self.input_size);
        let mut base = 0;
        let mut merkle_path: Vec<H::Output> = Vec::new();
        merkle_path.push(self.tree[leaf_idx]);
        (1..=self.depth).rev().enumerate().for_each(|(idx, depth)| {
            let layer_len = 1 << depth;
            let neighbour_idx = (leaf_idx >> idx) ^ 1;
            merkle_path.push(self.tree[base + neighbour_idx]);
            base += layer_len;
        });
        merkle_path
    }

    /// Check whether the merkle path is consistent with the root
    #[inline]
    pub fn check(committed_root: &H::Output, leaf_idx: usize, path: &[H::Output]) -> bool {
        let mut hasher = H::new();

        let leaf = path[0];
        let path_root = path[1..].iter().enumerate().fold(leaf, |acc, (idx, hash)| {
            if (leaf_idx >> idx) & 1 == 0 {
                hasher.update_hash_value(acc.as_ref());
                hasher.update_hash_value(hash.as_ref());
            } else {
                hasher.update_hash_value(hash.as_ref());
                hasher.update_hash_value(acc.as_ref());
            }
            hasher.output_reset()
        });

        path_root == *committed_root
    }
}
