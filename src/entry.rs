//! Decoding the deshredded bytes into entries and transactions.
//!
//! The payload of one complete shred run is a `BlockComponent`
//! (<https://github.com/anza-xyz/agave/blob/v4.2.0/entry/src/block_component.rs#L457>):
//! a `u64` little-endian entry count followed by that many entries. A zero
//! count means a block marker follows instead of entries
//! (<https://github.com/anza-xyz/agave/blob/v4.2.0/entry/src/block_component.rs#L548>);
//! markers carry no transactions, so they are reported and otherwise ignored.
//!
//! Agave serializes entries with `wincode`, not bincode. For legacy and v0
//! transactions the two formats are identical, but v1 transactions
//! (SIMD-0385) have a layout bincode cannot express: the signatures come after
//! the message without a length prefix, and counts are plain `u8`/`u16`.
//! `VersionedTransaction`'s `wincode` schema handles all three versions, which
//! is why this crate decodes with `wincode`, as the blockstore does
//! (<https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/blockstore.rs#L5206>),
//! and the `Entry` struct here mirrors
//! <https://github.com/anza-xyz/agave/blob/v4.2.0/entry/src/entry.rs#L45> field for field.

use {
    solana_hash::Hash,
    solana_transaction::versioned::VersionedTransaction,
    wincode::{SchemaRead, SchemaWrite, containers::Vec as WincodeVec, len::BincodeLen},
};

/// Upper bound on one batch, same as
/// <https://github.com/anza-xyz/agave/blob/v4.2.0/entry/src/entry.rs#L26>.
/// The length prefixes below use it as the preallocation limit.
pub const MAX_DATA_SHREDS_SIZE: usize = 32_768 * 1232;
type MaxDataShredsLen = BincodeLen<MAX_DATA_SHREDS_SIZE>;

#[derive(Debug, Clone, PartialEq, Eq, Default, SchemaRead, SchemaWrite)]
pub struct Entry {
    /// PoH hashes since the previous entry.
    pub num_hashes: u64,
    /// PoH hash after `num_hashes` hashes (mixed with the transactions).
    pub hash: Hash,
    #[wincode(with = "WincodeVec<VersionedTransaction, MaxDataShredsLen>")]
    pub transactions: Vec<VersionedTransaction>,
}

#[derive(SchemaRead, SchemaWrite)]
struct EntryBatchWire {
    #[wincode(with = "WincodeVec<Entry, MaxDataShredsLen>")]
    entries: Vec<Entry>,
}

pub enum BlockData {
    Entries(Vec<Entry>),
    BlockMarker,
}

/// Decode one complete shred run.
pub fn decode(bytes: &[u8]) -> Result<BlockData, wincode::ReadError> {
    if bytes.len() >= 8 && bytes[..8] == [0u8; 8] {
        return Ok(BlockData::BlockMarker);
    }
    // `deserialize` rather than `deserialize_exact`, as the blockstore does: a
    // final padded run can carry trailing zero bytes.
    wincode::deserialize::<EntryBatchWire>(bytes).map(|wire| BlockData::Entries(wire.entries))
}

/// Serialize entries the way a leader does before shredding them.
pub fn encode(entries: Vec<Entry>) -> Vec<u8> {
    wincode::serialize(&EntryBatchWire { entries }).expect("in-memory write cannot fail")
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        solana_message::{
            MessageHeader, VersionedMessage, compiled_instruction::CompiledInstruction, v1,
        },
        solana_signature::Signature,
    };

    #[test]
    fn v1_transaction_round_trips() {
        // SIMD-0385 layout: inline config, no lookup tables, signatures after
        // the message. bincode cannot read this; wincode does.
        let tx = VersionedTransaction {
            signatures: vec![Signature::from([7u8; 64])],
            message: VersionedMessage::V1(v1::Message {
                header: MessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed_accounts: 0,
                    num_readonly_unsigned_accounts: 1,
                },
                config: v1::TransactionConfig {
                    priority_fee: Some(5_000),
                    compute_unit_limit: Some(200_000),
                    loaded_accounts_data_size_limit: None,
                    heap_size: None,
                },
                lifetime_specifier: Hash::new_from_array([9u8; 32]),
                account_keys: vec![
                    solana_message::Address::new_from_array([1u8; 32]),
                    solana_message::Address::new_from_array([2u8; 32]),
                ],
                instructions: vec![CompiledInstruction {
                    program_id_index: 1,
                    accounts: vec![0],
                    data: vec![1, 2, 3],
                }],
            }),
        };
        let entries = vec![Entry {
            num_hashes: 3,
            hash: Hash::new_from_array([4u8; 32]),
            transactions: vec![tx],
        }];
        let bytes = encode(entries.clone());
        assert_eq!(bytes[..8], 1u64.to_le_bytes());
        match decode(&bytes).unwrap() {
            BlockData::Entries(decoded) => assert_eq!(decoded, entries),
            BlockData::BlockMarker => panic!("not a marker"),
        }
    }

    #[test]
    fn zero_count_is_a_block_marker() {
        let mut bytes = vec![0u8; 8];
        bytes.extend_from_slice(&[1, 0, 42]);
        assert!(matches!(decode(&bytes), Ok(BlockData::BlockMarker)));
        assert!(decode(&[1, 2, 3]).is_err());
        assert!(decode(&[9u8; 40]).is_err());
    }
}
