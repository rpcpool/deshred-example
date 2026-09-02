//! Zero-copy view of a deshredded segment: entries and transactions as
//! slices into the payload, nothing allocated, nothing copied.
//!
//! [`crate::entry::decode`] materializes every transaction into owned
//! structs, which costs a handful of heap allocations per transaction. A
//! consumer that only routes on the signature, the program ids, or a few
//! account keys can instead scan the segment once, learning only where each
//! transaction starts and ends, and read the fields it needs in place. This
//! is the approach of firedancer's `fd_txn` parser and of
//! `agave-transaction-view`; the latter cannot walk a stream (it rejects
//! trailing bytes), so the boundary scan lives here and its slices can be
//! handed to either.
//!
//! Wire layout walked here, all little-endian:
//!
//! ```text
//! segment  = entry count (u64) | entries
//! entry    = num_hashes (u64) | hash (32) | tx count (u64) | transactions
//! legacy   = sigs (shortvec) | header (3) | keys (shortvec of 32) |
//!            blockhash (32) | instructions (shortvec)
//! v0       = like legacy with a 0x80 version byte before the header and
//!            address table lookups after the instructions
//! v1       = 0x81 | header (3) | config mask (u32) | blockhash (32) |
//!            n_ix (u8) | n_keys (u8) | keys | config values |
//!            ix headers (4 each) | ix payloads | sigs (no count prefix)
//! ```
//!
//! Legacy and v0 are
//! <https://docs.anza.xyz/developing/programming-model/transactions>; v1 is
//! SIMD-0385 as implemented in
//! <https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/blockstore.rs#L5206>'s
//! wincode path. The scanner accepts exactly what the owned decoder accepts;
//! the fixture test proves the boundaries match wincode's byte for byte.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ViewError {
    #[error("segment truncated at byte {0}")]
    Truncated(usize),
    #[error("invalid shortvec length at byte {0}")]
    BadShortVec(usize),
    #[error("unknown transaction version {0:#04x}")]
    UnknownVersion(u8),
    #[error("unknown v1 config mask bit")]
    BadConfigMask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxVersion {
    Legacy,
    V0,
    V1,
}

/// One transaction, borrowed from the segment.
#[derive(Clone, Copy)]
pub struct TxView<'a> {
    bytes: &'a [u8],
    version: TxVersion,
    /// Where the signatures start (legacy/v0 after the count byte(s), v1 at
    /// the tail of the transaction).
    signatures_offset: u16,
    num_signatures: u8,
}

impl<'a> TxView<'a> {
    /// The exact serialized transaction, e.g. for `agave-transaction-view`
    /// or for submitting elsewhere.
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub const fn version(&self) -> TxVersion {
        self.version
    }

    pub const fn num_signatures(&self) -> u8 {
        self.num_signatures
    }

    /// The transaction id: its first signature.
    pub const fn signature(&self) -> &'a [u8; 64] {
        let offset = self.signatures_offset as usize;
        // The scanner verified the signatures are in bounds.
        let (_, rest) = self.bytes.split_at(offset);
        let (signature, _) = rest.split_first_chunk::<64>().unwrap();
        signature
    }
}

impl fmt::Debug for TxView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxView")
            .field("version", &self.version)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// One entry, transactions still serialized.
#[derive(Debug, Clone, Copy)]
pub struct EntryView<'a> {
    pub num_hashes: u64,
    pub hash: &'a [u8; 32],
    num_transactions: u64,
    /// The entry's transactions, back to back.
    transactions: &'a [u8],
}

impl<'a> EntryView<'a> {
    pub const fn num_transactions(&self) -> u64 {
        self.num_transactions
    }

    pub const fn transactions(&self) -> TxIter<'a> {
        TxIter {
            cursor: Cursor {
                bytes: self.transactions,
                offset: 0,
            },
            remaining: self.num_transactions,
        }
    }
}

pub struct TxIter<'a> {
    cursor: Cursor<'a>,
    remaining: u64,
}

impl<'a> Iterator for TxIter<'a> {
    type Item = Result<TxView<'a>, ViewError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(scan_transaction(&mut self.cursor).inspect_err(|_| self.remaining = 0))
    }
}

/// Iterate a segment without allocating. The scan is done lazily; an error
/// mid-segment ends the iteration with that error.
pub fn entries(segment: &[u8]) -> Result<EntryIter<'_>, ViewError> {
    let mut cursor = Cursor {
        bytes: segment,
        offset: 0,
    };
    let remaining = cursor.u64()?;
    Ok(EntryIter { cursor, remaining })
}

pub struct EntryIter<'a> {
    cursor: Cursor<'a>,
    remaining: u64,
}

impl<'a> Iterator for EntryIter<'a> {
    type Item = Result<EntryView<'a>, ViewError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(self.scan_entry().inspect_err(|_| self.remaining = 0))
    }
}

impl<'a> EntryIter<'a> {
    fn scan_entry(&mut self) -> Result<EntryView<'a>, ViewError> {
        let cursor = &mut self.cursor;
        let num_hashes = cursor.u64()?;
        let hash = cursor.array::<32>()?;
        let num_transactions = cursor.u64()?;
        let start = cursor.offset;
        for _ in 0..num_transactions {
            scan_transaction(cursor)?;
        }
        Ok(EntryView {
            num_hashes,
            hash,
            num_transactions,
            transactions: &cursor.bytes[start..cursor.offset],
        })
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    #[inline]
    fn take(&mut self, n: usize) -> Result<&'a [u8], ViewError> {
        let end = self
            .offset
            .checked_add(n)
            .filter(|&end| end <= self.bytes.len())
            .ok_or(ViewError::Truncated(self.offset))?;
        let taken = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(taken)
    }

    #[inline]
    fn u8(&mut self) -> Result<u8, ViewError> {
        Ok(self.take(1)?[0])
    }

    #[inline]
    fn u64(&mut self) -> Result<u64, ViewError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    #[inline]
    fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], ViewError> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    /// Solana's compact-u16: 7 bits per byte, at most 3 bytes.
    #[inline]
    fn shortvec_len(&mut self) -> Result<usize, ViewError> {
        let at = self.offset;
        let mut value = 0usize;
        for shift in [0u32, 7, 14] {
            let byte = self.u8()?;
            value |= usize::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ViewError::BadShortVec(at))
    }
}

fn scan_transaction<'a>(cursor: &mut Cursor<'a>) -> Result<TxView<'a>, ViewError> {
    let start = cursor.offset;
    let first = cursor
        .bytes
        .get(start)
        .copied()
        .ok_or(ViewError::Truncated(start))?;
    // Legacy and v0 start with the signature count, which is capped far below
    // 0x80; v1 starts with its 0x81 version byte (SIMD-0385).
    if first < 0x80 {
        scan_legacy_or_v0(cursor, start)
    } else if first == 0x81 {
        scan_v1(cursor, start)
    } else {
        Err(ViewError::UnknownVersion(first))
    }
}

fn scan_legacy_or_v0<'a>(cursor: &mut Cursor<'a>, start: usize) -> Result<TxView<'a>, ViewError> {
    let num_signatures = cursor.shortvec_len()?;
    let signatures_offset = (cursor.offset - start) as u16;
    cursor.take(num_signatures * 64)?;

    let message_first = cursor
        .bytes
        .get(cursor.offset)
        .copied()
        .ok_or(ViewError::Truncated(cursor.offset))?;
    let version = if message_first & 0x80 == 0 {
        TxVersion::Legacy
    } else if message_first == 0x80 {
        cursor.u8()?;
        TxVersion::V0
    } else {
        return Err(ViewError::UnknownVersion(message_first));
    };

    cursor.take(3)?; // header
    let num_keys = cursor.shortvec_len()?;
    cursor.take(num_keys * 32)?;
    cursor.take(32)?; // blockhash
    let num_instructions = cursor.shortvec_len()?;
    for _ in 0..num_instructions {
        cursor.u8()?; // program id index
        let num_accounts = cursor.shortvec_len()?;
        cursor.take(num_accounts)?;
        let data_len = cursor.shortvec_len()?;
        cursor.take(data_len)?;
    }
    if version == TxVersion::V0 {
        let num_lookups = cursor.shortvec_len()?;
        for _ in 0..num_lookups {
            cursor.take(32)?; // table address
            let writable = cursor.shortvec_len()?;
            cursor.take(writable)?;
            let readonly = cursor.shortvec_len()?;
            cursor.take(readonly)?;
        }
    }
    Ok(TxView {
        bytes: &cursor.bytes[start..cursor.offset],
        version,
        signatures_offset,
        num_signatures: num_signatures as u8,
    })
}

/// SIMD-0385: fixed-width counts, inline config, signatures at the tail
/// without a length prefix.
fn scan_v1<'a>(cursor: &mut Cursor<'a>, start: usize) -> Result<TxView<'a>, ViewError> {
    cursor.u8()?; // 0x81
    let num_signatures = cursor.u8()?; // header.num_required_signatures
    cursor.take(2)?; // rest of the header
    let mask = u32::from_le_bytes(*cursor.array::<4>()?);
    if mask & !0b1_1111 != 0 || (mask & 0b11 != 0 && mask & 0b11 != 0b11) {
        // Same rejection as the wincode reader: unknown bits do not
        // round-trip, and the priority fee occupies both of its bits or none.
        return Err(ViewError::BadConfigMask);
    }
    cursor.take(32)?; // lifetime specifier
    let num_instructions = usize::from(cursor.u8()?);
    let num_keys = usize::from(cursor.u8()?);
    cursor.take(num_keys * 32)?;
    let config_len = if mask & 0b11 != 0 { 8 } else { 0 }
        + if mask & 0b100 != 0 { 4 } else { 0 }
        + if mask & 0b1000 != 0 { 4 } else { 0 }
        + if mask & 0b1_0000 != 0 { 4 } else { 0 };
    cursor.take(config_len)?;
    let headers = cursor.take(num_instructions * 4)?;
    let payloads: usize = headers
        .chunks_exact(4)
        .map(|h| usize::from(h[1]) + usize::from(u16::from_le_bytes([h[2], h[3]])))
        .sum();
    cursor.take(payloads)?;
    let signatures_offset = (cursor.offset - start) as u16;
    cursor.take(usize::from(num_signatures) * 64)?;
    Ok(TxView {
        bytes: &cursor.bytes[start..cursor.offset],
        version: TxVersion::V1,
        signatures_offset,
        num_signatures,
    })
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            deshredder::{Config, Deshredder, EntryBatch},
            entry, fixture,
        },
    };

    /// Every boundary the scanner finds must match what wincode decodes:
    /// same entry framing, and per transaction the exact bytes wincode would
    /// re-serialize.
    #[test]
    fn boundaries_match_wincode_on_the_fixture() {
        let mut deshredder = Deshredder::new(Config::default());
        let mut batches: Vec<EntryBatch> = Vec::new();
        for record in fixture::Reader::open(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/mainnet.shreds"
        ))
        .unwrap()
        {
            deshredder.push(record.unwrap().packet, &mut batches);
        }
        assert!(!batches.is_empty());

        let mut transactions = 0usize;
        for batch in &batches {
            let segment = entry::encode(batch.entries.clone());
            let mut owned = batch.entries.iter();
            for entry_view in entries(&segment).unwrap() {
                let entry_view = entry_view.unwrap();
                let entry = owned.next().unwrap();
                assert_eq!(entry_view.num_hashes, entry.num_hashes);
                assert_eq!(entry_view.hash, &entry.hash.to_bytes());
                assert_eq!(
                    entry_view.num_transactions() as usize,
                    entry.transactions.len()
                );
                for (view, tx) in entry_view.transactions().zip(&entry.transactions) {
                    let view = view.unwrap();
                    let serialized = wincode::serialize(tx).unwrap();
                    assert_eq!(view.bytes(), serialized, "boundary mismatch");
                    assert_eq!(view.signature(), tx.signatures[0].as_array());
                    transactions += 1;
                }
            }
            assert!(owned.next().is_none());
        }
        assert!(
            transactions > 1000,
            "fixture yielded {transactions} transactions"
        );
    }

    #[test]
    fn truncated_and_garbage_segments_error() {
        assert!(entries(&[]).is_err());
        let segment = entry::encode(vec![]);
        assert_eq!(entries(&segment).unwrap().count(), 0);
        // One entry claimed, nothing behind it.
        let mut bad = 1u64.to_le_bytes().to_vec();
        bad.extend_from_slice(&[0; 4]);
        let views: Vec<_> = entries(&bad).unwrap().collect();
        assert!(views.last().unwrap().is_err());
    }
}
