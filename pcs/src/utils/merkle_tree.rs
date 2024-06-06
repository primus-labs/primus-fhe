use sha3::{Digest, Sha3_256};

type Hash = [u8; 32];

/// Merkle Tree for Vector Commitment
#[derive(Debug, Clone, Default)]
pub struct MerkleTree {
    /// the depth of the merkle tree
    pub depth: usize,
    /// the root of the merkle tree
    pub root: Hash,
    /// the merkle tree
    pub tree: Vec<Hash>,
}

impl MerkleTree {
    /// instantiate a merkle tree by committing the leaves
    pub fn commit(mut tree: Vec<Hash>) -> Self {
        // resize the size from leaves size to tree size
        let depth = tree.len().next_power_of_two().ilog2() as usize;
        let size = (1 << (depth + 1)) - 1;
        tree.resize(size, Hash::default());

        // merklize the leaves
        let mut hasher = Sha3_256::new();
        let mut base = 0; // use base to index the start of the lower layer
        for depth in (1..=depth).rev() {
            // view the lower layer as the input and the upper layer as its output
            let input_len = 1 << depth;
            let output_len = input_len >> 1;
            let (inputs, outputs) =
                tree[base..base + input_len + output_len].split_at_mut(input_len);
            // compute the output of the hash function given the input
            inputs
                .chunks_exact(2)
                .zip(outputs.iter_mut())
                .for_each(|(input, output)| {
                    hasher.update(input[0]);
                    hasher.update(input[1]);
                    output.copy_from_slice(hasher.finalize_reset().as_slice());
                });
            base += input_len;
        }

        let root = *tree.last().unwrap();

        Self { depth, root, tree }
    }

    /// return merkle paths of the indexed leaf
    /// which consists of the leaf hash and neighbour hashes
    #[inline]
    pub fn query(&self, leaf_idx: usize) -> Vec<Hash> {
        let mut base = 0;
        let mut merkle_path: Vec<Hash> = Vec::new();
        merkle_path.push(self.tree[leaf_idx]);
        (1..=self.depth).rev().enumerate().for_each(|(idx, depth)| {
            let layer_len = 1 << depth;
            let neighbour_idx = (leaf_idx >> idx) ^ 1;
            merkle_path.push(self.tree[base + neighbour_idx]);
            base += layer_len;
        });
        merkle_path
    }

    /// check whether the merkle path is consistent with the root
    #[inline]
    pub fn check(committed_root: &Hash, leaf_idx: &usize, path: &[Hash]) -> bool {
        let mut hasher = Sha3_256::new();

        let leaf = path[0];
        let path_root = path[1..].iter().enumerate().fold(leaf, |acc, (idx, hash)| {
            if (leaf_idx >> idx) & 1 == 0 {
                hasher.update(acc);
                hasher.update(hash);
            } else {
                hasher.update(hash);
                hasher.update(acc);
            }
            hasher
                .finalize_reset()
                .as_slice()
                .try_into()
                .expect("hasher doesn't return Hash [u8;32]")
        });

        path_root == *committed_root
    }
}
