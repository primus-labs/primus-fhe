use crate::utils::hash::Hash;

/// Root of the Merkle Tree only
#[derive(Debug, Clone, Default)]
pub struct MerkleRoot<H: Hash> {
    /// the depth of the merkle tree
    pub depth: usize,
    /// the root of the merkle tree
    pub root: H::Output,
}

impl<H: Hash> MerkleRoot<H> {
    /// instantiate a merkle root
    pub fn new(depth: usize, root: H::Output) -> Self {
        Self { depth, root }
    }
}

/// Merkle Tree for Vector Commitment
#[derive(Debug, Clone, Default)]
pub struct MerkleTree<H: Hash> {
    /// the depth of the merkle tree
    pub depth: usize,
    /// the root of the merkle tree
    pub root: H::Output,
    /// the merkle tree
    pub tree: Vec<H::Output>,
}

impl<H: Hash> MerkleTree<H> {
    /// instantiate a merkle tree by committing the leaves
    pub fn new(mut tree: Vec<H::Output>) -> Self {
        // resize the size from leaves size to tree size
        let depth = tree.len().next_power_of_two().ilog2() as usize;
        let size = (1 << (depth + 1)) - 1;
        tree.resize(size, H::Output::default());

        // merklize the leaves
        let mut hasher = H::new();
        // use base to index the start of the lower layer
        let mut base = 0;
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
                    hasher.update_hash_value(input[0]);
                    hasher.update_hash_value(input[1]);
                    *output = hasher.output_reset();
                });
            base += input_len;
        }

        let root = *tree.last().unwrap();

        Self { depth, root, tree }
    }

    /// return merkle paths of the indexed leaf
    /// which consists of the leaf hash and neighbour hashes
    #[inline]
    pub fn query(&self, leaf_idx: usize) -> Vec<H::Output> {
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

    /// check whether the merkle path is consistent with the root
    #[inline]
    pub fn check(committed_root: H::Output, leaf_idx: usize, path: &[H::Output]) -> bool {
        let mut hasher = H::new();

        let leaf = path[0];
        let path_root = path[1..].iter().enumerate().fold(leaf, |acc, (idx, hash)| {
            if (leaf_idx >> idx) & 1 == 0 {
                hasher.update_hash_value(acc);
                hasher.update_hash_value(*hash); ////?
            } else {
                hasher.update_hash_value(*hash);
                hasher.update_hash_value(acc);
            }
            hasher.output_reset()
        });

        path_root == committed_root
    }
}
