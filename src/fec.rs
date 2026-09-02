//! One FEC set: 32 data shreds protected by 32 Reed-Solomon code shreds.
//!
//! Any 32 of the 64 shreds are enough to rebuild the data shreds, so a set can
//! be completed before every data shred has arrived. Recovery follows
//! <https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/shred/merkle.rs#L669>
//! with one deliberate difference: agave rebuilds the Merkle tree over the
//! recovered set, both to double check the reconstruction and to attach
//! proofs to the recovered shreds, which it retransmits. Here every shard fed
//! into the reconstruction already had its own proof verified against the
//! set's signed root on insert, nothing is retransmitted, and recovered
//! shreds are only read for their data and flags, so the tree rebuild is
//! skipped and recovered shreds carry zeroed proof bytes.

use crate::{
    merkle::Hash32,
    shred::{
        CODE_SHREDS_PER_FEC_SET, DATA_SHREDS_PER_FEC_SET, SIGNATURE_SIZE, Shred, ShredError,
        ShredKind,
    },
};

pub type ReedSolomon = reed_solomon_erasure::galois_8::ReedSolomon;

pub fn reed_solomon() -> ReedSolomon {
    ReedSolomon::new(DATA_SHREDS_PER_FEC_SET, CODE_SHREDS_PER_FEC_SET).unwrap()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insert {
    New,
    Duplicate,
    /// Code shred for a set that already has all its data.
    Unneeded,
    Rejected(Reject),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Proof does not lead back to a root at all.
    BadProof,
    /// Root differs from the other shreds of this set.
    MerkleRootMismatch,
    /// Leader signature differs from the other shreds of this set.
    SignatureMismatch,
}

#[derive(Debug, thiserror::Error)]
pub enum RecoverError {
    #[error("reed-solomon: {0}")]
    ReedSolomon(#[from] reed_solomon_erasure::Error),
    #[error("recovered shred is malformed: {0}")]
    InvalidShred(#[from] ShredError),
    #[error("recovered shred {index} has the wrong headers")]
    WrongHeaders { index: u32 },
}

pub struct FecSet {
    data: [Option<Shred>; DATA_SHREDS_PER_FEC_SET],
    code: [Option<Shred>; CODE_SHREDS_PER_FEC_SET],
    num_data: usize,
    num_code: usize,
    // Set by the first accepted shred; every later one must agree. Without
    // the leader's pubkey there is no way to tell which of two roots is the
    // signed one, so a corrupted first shred costs the whole set. Leader
    // signature verification would fix that; it needs the leader schedule.
    root: Option<Hash32>,
    signature: [u8; SIGNATURE_SIZE],
}

impl Default for FecSet {
    fn default() -> Self {
        Self {
            data: [const { None }; DATA_SHREDS_PER_FEC_SET],
            code: [const { None }; CODE_SHREDS_PER_FEC_SET],
            num_data: 0,
            num_code: 0,
            root: None,
            signature: [0; SIGNATURE_SIZE],
        }
    }
}

impl FecSet {
    pub fn insert(&mut self, shred: Shred) -> Insert {
        // Cheap checks first: the Merkle root costs seven SHA-256 rounds, and
        // in the common case every code shred arrives after its set is done.
        if shred.kind() == ShredKind::Code && self.is_complete() {
            return Insert::Unneeded;
        }
        if self.get(&shred).is_some() {
            return Insert::Duplicate;
        }
        let Some(root) = shred.merkle_root() else {
            return Insert::Rejected(Reject::BadProof);
        };
        match self.root {
            None => {
                self.root = Some(root);
                self.signature.copy_from_slice(shred.signature());
            }
            Some(known) if known != root => return Insert::Rejected(Reject::MerkleRootMismatch),
            Some(_) if self.signature != shred.signature() => {
                return Insert::Rejected(Reject::SignatureMismatch);
            }
            Some(_) => {}
        }
        let position = shred.erasure_shard_index();
        match shred.kind() {
            ShredKind::Data => {
                self.data[position] = Some(shred);
                self.num_data += 1;
            }
            ShredKind::Code => {
                self.code[position - DATA_SHREDS_PER_FEC_SET] = Some(shred);
                self.num_code += 1;
            }
        }
        if self.is_complete() {
            self.drop_code();
        }
        Insert::New
    }

    fn get(&self, shred: &Shred) -> Option<&Shred> {
        let position = shred.erasure_shard_index();
        match shred.kind() {
            ShredKind::Data => self.data[position].as_ref(),
            ShredKind::Code => self.code[position - DATA_SHREDS_PER_FEC_SET].as_ref(),
        }
    }

    pub const fn data(&self, position: usize) -> Option<&Shred> {
        self.data[position].as_ref()
    }

    /// All data shreds present; the code shreds have been dropped.
    pub const fn is_complete(&self) -> bool {
        self.num_data == DATA_SHREDS_PER_FEC_SET
    }

    pub const fn can_recover(&self) -> bool {
        !self.is_complete()
            && self.num_code > 0
            && self.num_data + self.num_code >= DATA_SHREDS_PER_FEC_SET
    }

    fn drop_code(&mut self) {
        self.code = [const { None }; CODE_SHREDS_PER_FEC_SET];
        self.num_code = 0;
    }

    fn any_shred(&self) -> &Shred {
        self.code
            .iter()
            .chain(self.data.iter())
            .flatten()
            .next()
            .expect("can_recover implies at least one shred")
    }

    /// Rebuild the missing data shreds. Returns their indexes.
    pub fn recover(&mut self, rs: &ReedSolomon) -> Result<Vec<u32>, RecoverError> {
        debug_assert!(self.can_recover());
        let template = self.any_shred();
        let shard_len = template.erasure_shard().len();
        let chained_root = template.chained_merkle_root().to_vec();
        let retransmitter_signature = template.retransmitter_signature().map(<[u8]>::to_vec);
        let slot = template.slot();
        let fec_set_index = template.fec_set_index();
        let version = template.version();

        let mut shards: Vec<(Vec<u8>, bool)> = self
            .data
            .iter()
            .chain(self.code.iter())
            .map(|shred| match shred {
                Some(shred) => (shred.erasure_shard().to_vec(), true),
                None => (vec![0u8; shard_len], false),
            })
            .collect();
        // Only the data shards; reconstructing the missing parity would be
        // wasted work, nothing reads it.
        rs.reconstruct_data(&mut shards)?;

        let mut recovered = Vec::new();
        for (position, (shard, present)) in shards.iter().take(DATA_SHREDS_PER_FEC_SET).enumerate()
        {
            if *present {
                continue;
            }
            // Same layout as a received data shred: the shard already holds
            // every header after the signature. The proof bytes stay zero.
            let mut bytes = vec![0u8; crate::shred::DATA_SHRED_SIZE];
            bytes[..SIGNATURE_SIZE].copy_from_slice(&self.signature);
            bytes[SIGNATURE_SIZE..SIGNATURE_SIZE + shard.len()].copy_from_slice(shard);
            bytes[SIGNATURE_SIZE + shard.len()..SIGNATURE_SIZE + shard.len() + chained_root.len()]
                .copy_from_slice(&chained_root);
            if let Some(sig) = &retransmitter_signature {
                let end = bytes.len();
                bytes[end - SIGNATURE_SIZE..].copy_from_slice(sig);
            }
            let shred = Shred::parse(bytes::Bytes::from(bytes))?;
            let index = fec_set_index + position as u32;
            if shred.kind() != ShredKind::Data
                || shred.slot() != slot
                || shred.index() != index
                || shred.fec_set_index() != fec_set_index
                || shred.version() != version
            {
                return Err(RecoverError::WrongHeaders { index });
            }
            self.data[position] = Some(shred);
            self.num_data += 1;
            recovered.push(index);
        }
        self.drop_code();
        Ok(recovered)
    }
}
