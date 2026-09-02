//! Merkle tree over one FEC set, as in
//! <https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/shred/merkle_tree.rs>.
//!
//! Leaves are the 64 shreds of a set in erasure-shard order (32 data, then 32
//! code). Internal nodes hash the first 20 bytes of each child; a node with
//! no right sibling pairs with itself. The leader signs the root, and every
//! shred carries the proof for its own leaf.

use solana_sha256_hasher::hashv;

pub type Hash32 = [u8; 32];
pub type ProofEntry = [u8; PROOF_ENTRY_SIZE];

pub const PROOF_ENTRY_SIZE: usize = 20;
/// Proof entries for a 64 leaf tree.
pub const PROOF_ENTRIES_FOR_32_32: u8 = 6;

// Domain separation against second preimage attacks, same prefixes as
// <https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/shred/merkle_tree.rs#L17>.
const LEAF_PREFIX: &[u8] = b"\x00SOLANA_MERKLE_SHREDS_LEAF";
const NODE_PREFIX: &[u8] = b"\x01SOLANA_MERKLE_SHREDS_NODE";

pub fn leaf(bytes: &[u8]) -> Hash32 {
    hashv(&[LEAF_PREFIX, bytes]).to_bytes()
}

fn join(left: &[u8], right: &[u8]) -> Hash32 {
    hashv(&[
        NODE_PREFIX,
        &left[..PROOF_ENTRY_SIZE],
        &right[..PROOF_ENTRY_SIZE],
    ])
    .to_bytes()
}

/// Walk a proof up from `leaf` at `index`. `proof` is the flattened 20-byte
/// entries. Returns `None` if the proof is too short for the index.
/// <https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/shred/merkle_tree.rs#L115>
pub fn root_from_proof(index: usize, leaf: Hash32, proof: &[u8]) -> Option<Hash32> {
    let (index, root) =
        proof
            .chunks_exact(PROOF_ENTRY_SIZE)
            .fold((index, leaf), |(index, node), sibling| {
                let parent = if index % 2 == 0 {
                    join(&node, sibling)
                } else {
                    join(sibling, &node)
                };
                (index >> 1, parent)
            });
    (index == 0).then_some(root)
}

/// A full tree, used to check a recovered set and to rebuild the proofs of
/// recovered shreds. <https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/shred/merkle_tree.rs#L47>
pub struct Tree {
    // Leaves first, then each level up to the root.
    nodes: Vec<Hash32>,
    num_leaves: usize,
}

impl Tree {
    pub fn new(leaves: Vec<Hash32>) -> Self {
        assert!(!leaves.is_empty());
        let num_leaves = leaves.len();
        let mut nodes = leaves;
        let mut offset = 0;
        let mut size = num_leaves;
        while size > 1 {
            for i in (offset..offset + size).step_by(2) {
                let right = (i + 1).min(offset + size - 1);
                let parent = join(&nodes[i], &nodes[right]);
                nodes.push(parent);
            }
            offset += size;
            size = size.div_ceil(2);
        }
        Self { nodes, num_leaves }
    }

    pub fn root(&self) -> Hash32 {
        *self.nodes.last().unwrap()
    }

    pub fn proof(&self, mut index: usize) -> Vec<ProofEntry> {
        assert!(index < self.num_leaves);
        let mut proof = Vec::new();
        let mut offset = 0;
        let mut size = self.num_leaves;
        while size > 1 {
            let sibling = &self.nodes[offset + (index ^ 1).min(size - 1)];
            proof.push(sibling[..PROOF_ENTRY_SIZE].try_into().unwrap());
            offset += size;
            size = size.div_ceil(2);
            index >>= 1;
        }
        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs_reproduce_root() {
        for n in [1usize, 2, 3, 5, 64] {
            let leaves: Vec<Hash32> = (0..n).map(|i| leaf(&[i as u8; 10])).collect();
            let tree = Tree::new(leaves.clone());
            for (i, l) in leaves.iter().enumerate() {
                let proof: Vec<u8> = tree.proof(i).concat();
                assert_eq!(
                    root_from_proof(i, *l, &proof),
                    Some(tree.root()),
                    "n={n} i={i}"
                );
            }
        }
        let tree = Tree::new((0..64).map(|i| leaf(&[i])).collect());
        assert_eq!(tree.proof(0).len(), PROOF_ENTRIES_FOR_32_32 as usize);
    }

    #[test]
    fn short_proof_is_rejected() {
        let tree = Tree::new((0..64).map(|i| leaf(&[i])).collect());
        let proof: Vec<u8> = tree.proof(5).concat();
        assert_eq!(root_from_proof(5, leaf(&[5]), &proof[..40]), None);
        assert_ne!(root_from_proof(6, leaf(&[5]), &proof), Some(tree.root()));
    }
}
