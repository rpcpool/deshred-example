//! Shred wire format: parsing and stateless validation.
//!
//! A shred is one UDP datagram. Mainnet only carries chained Merkle shreds
//! (the only variants left in agave v4.2, see
//! <https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/shred.rs#L250>),
//! so that is the only layout handled here. Every offset below is a fixed
//! position in the datagram:
//!
//! ```text
//! offset size  field
//! 0      64    leader signature over the FEC set's Merkle root
//! 64     1     variant: high nibble 0x9/0xb = data, 0x6/0x7 = code
//!              (0xb/0x7 = resigned); low nibble = Merkle proof entries
//! 65     8     slot (LE)
//! 73     4     shred index (LE)
//! 77     2     shred version (LE)
//! 79     4     FEC set index (LE)
//! data shreds:                         code shreds:
//! 83     2     parent offset           83  2  num data shreds
//! 85     1     flags                   85  2  num coding shreds
//! 86     2     size (headers + data)   87  2  position in FEC set
//! 88     ...   entry bytes             89  ... erasure coded shard
//! ```
//!
//! After the data buffer (or coded shard) comes the chained Merkle root
//! (32 bytes), the Merkle proof (20 bytes per entry) and, on resigned
//! variants, a trailing 64-byte retransmitter signature. Data shreds are
//! exactly 1203 bytes, code shreds 1228; a repair response may append a
//! 4-byte nonce, which is ignored.
//!
//! Sizes and layout:
//! <https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/shred/merkle.rs#L41>.
//!
//! The checks in [`Shred::parse`] mirror what agave does before a shred is
//! allowed into the blockstore: `sanitize` for data and code shreds
//! (<https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/shred/shred_data.rs#L12>,
//! <https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/shred/shred_code.rs#L34>)
//! and the stateless part of `should_discard_shred`
//! (<https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/shred/filter.rs#L277>).
//! What is not checked here: the leader signature (needs the leader
//! schedule) and the Merkle root, which is checked per FEC set in
//! [`crate::fec`].

use {
    crate::merkle::{self, Hash32, PROOF_ENTRIES_FOR_32_32, PROOF_ENTRY_SIZE},
    bytes::Bytes,
    std::fmt,
};

/// Wire size of a data shred.
pub const DATA_SHRED_SIZE: usize = 1203;
/// Wire size of a code shred.
pub const CODE_SHRED_SIZE: usize = 1228;
/// Data shreds in one FEC set. Agave rejects any other erasure config.
pub const DATA_SHREDS_PER_FEC_SET: usize = 32;
/// Code shreds in one FEC set.
pub const CODE_SHREDS_PER_FEC_SET: usize = 32;
/// Exclusive upper bound on a data or code shred index within a slot.
pub const MAX_SHREDS_PER_SLOT: u32 = 32_768;
/// Largest UDP payload a shred packet can have (shred + repair nonce).
pub const MAX_PACKET_SIZE: usize = 1232;

pub const SIGNATURE_SIZE: usize = 64;
pub const DATA_HEADERS_SIZE: usize = 88;
pub const CODE_HEADERS_SIZE: usize = 89;
const MERKLE_ROOT_SIZE: usize = 32;
/// Entry bytes in a regular (unsigned, 32:32) data shred.
pub const DATA_CAPACITY: usize = match capacity(ShredKind::Data, PROOF_ENTRIES_FOR_32_32, false) {
    Some(n) => n,
    None => unreachable!(),
};

const VARIANT_OFFSET: usize = 64;
const SLOT_OFFSET: usize = 65;
const INDEX_OFFSET: usize = 73;
const VERSION_OFFSET: usize = 77;
const FEC_SET_INDEX_OFFSET: usize = 79;
const PARENT_OFFSET_OFFSET: usize = 83;
const FLAGS_OFFSET: usize = 85;
const SIZE_OFFSET: usize = 86;
const NUM_DATA_OFFSET: usize = 83;
const NUM_CODE_OFFSET: usize = 85;
const POSITION_OFFSET: usize = 87;

// Flags: <https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/shred.rs#L152>.
/// Flag bit: this data shred ends an entry batch.
pub const FLAG_DATA_COMPLETE: u8 = 0b0100_0000;
/// Flag bits: this data shred is the last one in its slot. The value has the
/// data-complete bit set too, so last-in-slot always implies data-complete.
pub const FLAG_LAST_IN_SLOT: u8 = 0b1100_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShredKind {
    Data,
    Code,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ShredError {
    #[error("packet shorter than a shred ({0} bytes)")]
    TooShort(usize),
    #[error("unknown shred variant {0:#04x}")]
    InvalidVariant(u8),
    #[error("proof size {0} leaves no room for data")]
    InvalidProofSize(u8),
    #[error("shred index {0} out of range")]
    IndexOutOfRange(u32),
    #[error("index {index} not inside FEC set {fec_set_index}")]
    FecSetMisaligned { index: u32, fec_set_index: u32 },
    #[error("parent offset {parent_offset} invalid for slot {slot}")]
    InvalidParentOffset { slot: u64, parent_offset: u16 },
    #[error("invalid data shred flags {0:#04x}")]
    InvalidFlags(u8),
    #[error("data size field {0} out of range")]
    InvalidSize(u16),
    #[error("erasure config {num_data}:{num_code} position {position} is not 32:32")]
    InvalidErasureConfig {
        num_data: u16,
        num_code: u16,
        position: u16,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Header {
    Data {
        parent_offset: u16,
        flags: u8,
        size: u16,
    },
    Code {
        position: u16,
    },
}

/// A validated shred. The bytes are a refcounted slice (`Bytes`), so shreds
/// received in one batch share a single allocation and cloning is cheap.
#[derive(Clone, PartialEq, Eq)]
pub struct Shred {
    bytes: Bytes,
    kind: ShredKind,
    resigned: bool,
    proof_size: u8,
    slot: u64,
    index: u32,
    version: u16,
    fec_set_index: u32,
    /// Entry bytes (data) or coded shard (code) the variant can hold.
    capacity: usize,
    header: Header,
}

impl fmt::Debug for Shred {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shred")
            .field("kind", &self.kind)
            .field("slot", &self.slot)
            .field("index", &self.index)
            .field("fec_set_index", &self.fec_set_index)
            .field("version", &self.version)
            .field("resigned", &self.resigned)
            .finish()
    }
}

#[inline]
fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

#[inline]
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

#[inline]
fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// Bytes usable for entries (data) or the coded shard (code) for a variant.
/// Same arithmetic as <https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/shred/merkle.rs#L312>.
pub const fn capacity(kind: ShredKind, proof_size: u8, resigned: bool) -> Option<usize> {
    let (total, headers) = match kind {
        ShredKind::Data => (DATA_SHRED_SIZE, DATA_HEADERS_SIZE),
        ShredKind::Code => (CODE_SHRED_SIZE, CODE_HEADERS_SIZE),
    };
    let overhead = headers
        + MERKLE_ROOT_SIZE
        + proof_size as usize * PROOF_ENTRY_SIZE
        + if resigned { SIGNATURE_SIZE } else { 0 };
    total.checked_sub(overhead)
}

impl Shred {
    /// Parse and validate one datagram. The buffer is truncated to the wire
    /// size of the variant (dropping a repair nonce if present).
    pub fn parse(bytes: impl Into<Bytes>) -> Result<Self, ShredError> {
        let mut bytes = bytes.into();
        let variant = *bytes
            .get(VARIANT_OFFSET)
            .ok_or(ShredError::TooShort(bytes.len()))?;
        let (kind, resigned) = match variant & 0xF0 {
            0x90 => (ShredKind::Data, false),
            0xB0 => (ShredKind::Data, true),
            0x60 => (ShredKind::Code, false),
            0x70 => (ShredKind::Code, true),
            _ => return Err(ShredError::InvalidVariant(variant)),
        };
        let proof_size = variant & 0x0F;
        let size = match kind {
            ShredKind::Data => DATA_SHRED_SIZE,
            ShredKind::Code => CODE_SHRED_SIZE,
        };
        if bytes.len() < size {
            return Err(ShredError::TooShort(bytes.len()));
        }
        bytes.truncate(size);
        let capacity =
            capacity(kind, proof_size, resigned).ok_or(ShredError::InvalidProofSize(proof_size))?;

        let slot = u64_at(&bytes, SLOT_OFFSET);
        let index = u32_at(&bytes, INDEX_OFFSET);
        let version = u16_at(&bytes, VERSION_OFFSET);
        let fec_set_index = u32_at(&bytes, FEC_SET_INDEX_OFFSET);
        if index >= MAX_SHREDS_PER_SLOT {
            return Err(ShredError::IndexOutOfRange(index));
        }

        let header = match kind {
            ShredKind::Data => {
                // Data index space: the set starts on a 32-aligned index and
                // the shred sits inside its own set.
                if !fec_set_index.is_multiple_of(DATA_SHREDS_PER_FEC_SET as u32)
                    || index < fec_set_index
                    || index - fec_set_index >= DATA_SHREDS_PER_FEC_SET as u32
                {
                    return Err(ShredError::FecSetMisaligned {
                        index,
                        fec_set_index,
                    });
                }
                let parent_offset = u16_at(&bytes, PARENT_OFFSET_OFFSET);
                // Zero means "slot 0 has no parent"; anywhere else the shred
                // would be its own parent.
                if (parent_offset == 0 && slot != 0) || u64::from(parent_offset) > slot {
                    return Err(ShredError::InvalidParentOffset {
                        slot,
                        parent_offset,
                    });
                }
                let flags = bytes[FLAGS_OFFSET];
                let last_in_slot = flags & FLAG_LAST_IN_SLOT == FLAG_LAST_IN_SLOT;
                // Bit 7 on its own is not a valid flag byte, and the last shred
                // of a slot always closes its FEC set.
                if (flags & 0x80 != 0 && flags & FLAG_DATA_COMPLETE == 0)
                    || (last_in_slot && !(index + 1).is_multiple_of(DATA_SHREDS_PER_FEC_SET as u32))
                {
                    return Err(ShredError::InvalidFlags(flags));
                }
                let size = u16_at(&bytes, SIZE_OFFSET);
                if usize::from(size) < DATA_HEADERS_SIZE
                    || usize::from(size) > DATA_HEADERS_SIZE + capacity
                {
                    return Err(ShredError::InvalidSize(size));
                }
                Header::Data {
                    parent_offset,
                    flags,
                    size,
                }
            }
            ShredKind::Code => {
                let num_data = u16_at(&bytes, NUM_DATA_OFFSET);
                let num_code = u16_at(&bytes, NUM_CODE_OFFSET);
                let position = u16_at(&bytes, POSITION_OFFSET);
                // Code shreds have their own index space (`index - position`
                // is the first code index of the set) but share
                // `fec_set_index` with the data shreds they protect.
                if usize::from(num_data) != DATA_SHREDS_PER_FEC_SET
                    || usize::from(num_code) != CODE_SHREDS_PER_FEC_SET
                    || usize::from(position) >= CODE_SHREDS_PER_FEC_SET
                    || u32::from(position) > index
                    || !fec_set_index.is_multiple_of(DATA_SHREDS_PER_FEC_SET as u32)
                {
                    return Err(ShredError::InvalidErasureConfig {
                        num_data,
                        num_code,
                        position,
                    });
                }
                Header::Code { position }
            }
        };

        Ok(Self {
            bytes,
            kind,
            resigned,
            proof_size,
            slot,
            index,
            version,
            fec_set_index,
            capacity,
            header,
        })
    }

    pub const fn kind(&self) -> ShredKind {
        self.kind
    }

    pub fn is_data(&self) -> bool {
        self.kind == ShredKind::Data
    }

    pub const fn slot(&self) -> u64 {
        self.slot
    }

    pub const fn index(&self) -> u32 {
        self.index
    }

    pub const fn version(&self) -> u16 {
        self.version
    }

    pub const fn fec_set_index(&self) -> u32 {
        self.fec_set_index
    }

    pub const fn resigned(&self) -> bool {
        self.resigned
    }

    pub const fn proof_size(&self) -> u8 {
        self.proof_size
    }

    /// Full wire bytes (without repair nonce).
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn signature(&self) -> &[u8] {
        &self.bytes[..SIGNATURE_SIZE]
    }

    pub fn parent_slot(&self) -> Option<u64> {
        match self.header {
            Header::Data { parent_offset, .. } => Some(self.slot - u64::from(parent_offset)),
            Header::Code { .. } => None,
        }
    }

    pub const fn flags(&self) -> Option<u8> {
        match self.header {
            Header::Data { flags, .. } => Some(flags),
            Header::Code { .. } => None,
        }
    }

    pub fn data_complete(&self) -> bool {
        self.flags().is_some_and(|f| f & FLAG_DATA_COMPLETE != 0)
    }

    pub fn last_in_slot(&self) -> bool {
        self.flags()
            .is_some_and(|f| f & FLAG_LAST_IN_SLOT == FLAG_LAST_IN_SLOT)
    }

    /// Entry bytes carried by a data shred; empty for code shreds.
    pub fn data(&self) -> &[u8] {
        match self.header {
            Header::Data { size, .. } => &self.bytes[DATA_HEADERS_SIZE..usize::from(size)],
            Header::Code { .. } => &[],
        }
    }

    /// Range of the payload that takes part in erasure coding. For data
    /// shreds this starts right after the signature and so includes the
    /// headers, which is how recovery gets the headers of a missing shred.
    /// Offsets: <https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/shred/merkle.rs#L159>
    /// and <https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/shred/merkle.rs#L239>.
    pub fn erasure_shard(&self) -> &[u8] {
        let range = match self.kind {
            ShredKind::Data => SIGNATURE_SIZE..DATA_HEADERS_SIZE + self.capacity,
            ShredKind::Code => CODE_HEADERS_SIZE..CODE_HEADERS_SIZE + self.capacity,
        };
        &self.bytes[range]
    }

    /// Position in the FEC set's erasure batch: data shreds first, then code.
    pub fn erasure_shard_index(&self) -> usize {
        match self.header {
            Header::Data { .. } => (self.index - self.fec_set_index) as usize,
            Header::Code { position } => DATA_SHREDS_PER_FEC_SET + usize::from(position),
        }
    }

    const fn proof_offset(&self) -> usize {
        let headers = match self.kind {
            ShredKind::Data => DATA_HEADERS_SIZE,
            ShredKind::Code => CODE_HEADERS_SIZE,
        };
        headers + self.capacity + MERKLE_ROOT_SIZE
    }

    /// Merkle root of the previous FEC set, as carried by this shred.
    pub fn chained_merkle_root(&self) -> &[u8] {
        let end = self.proof_offset();
        &self.bytes[end - MERKLE_ROOT_SIZE..end]
    }

    pub fn merkle_proof(&self) -> &[u8] {
        let start = self.proof_offset();
        &self.bytes[start..start + usize::from(self.proof_size) * PROOF_ENTRY_SIZE]
    }

    /// Retransmitter signature on resigned variants.
    pub fn retransmitter_signature(&self) -> Option<&[u8]> {
        self.resigned
            .then(|| &self.bytes[self.bytes.len() - SIGNATURE_SIZE..])
    }

    /// Merkle leaf: everything between the leader signature (data) or the
    /// headers (code) and the proof, which includes the chained root.
    /// <https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/shred/merkle.rs#L396>
    pub fn merkle_leaf(&self) -> Hash32 {
        let start = match self.kind {
            ShredKind::Data => SIGNATURE_SIZE,
            ShredKind::Code => CODE_HEADERS_SIZE,
        };
        merkle::leaf(&self.bytes[start..self.proof_offset()])
    }

    /// Merkle root of the FEC set recomputed from this shred's own proof.
    /// This is the value the leader signed; all shreds of a set share it.
    pub fn merkle_root(&self) -> Option<Hash32> {
        merkle::root_from_proof(
            self.erasure_shard_index(),
            self.merkle_leaf(),
            self.merkle_proof(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_shred() -> Vec<u8> {
        let mut s = vec![0u8; DATA_SHRED_SIZE];
        s[VARIANT_OFFSET] = 0x96;
        s[SLOT_OFFSET..SLOT_OFFSET + 8].copy_from_slice(&1000u64.to_le_bytes());
        s[INDEX_OFFSET..INDEX_OFFSET + 4].copy_from_slice(&35u32.to_le_bytes());
        s[FEC_SET_INDEX_OFFSET..FEC_SET_INDEX_OFFSET + 4].copy_from_slice(&32u32.to_le_bytes());
        s[PARENT_OFFSET_OFFSET..PARENT_OFFSET_OFFSET + 2].copy_from_slice(&1u16.to_le_bytes());
        s[SIZE_OFFSET..SIZE_OFFSET + 2].copy_from_slice(&500u16.to_le_bytes());
        s
    }

    fn code_shred() -> Vec<u8> {
        let mut s = vec![0u8; CODE_SHRED_SIZE];
        s[VARIANT_OFFSET] = 0x66;
        s[SLOT_OFFSET..SLOT_OFFSET + 8].copy_from_slice(&1000u64.to_le_bytes());
        s[INDEX_OFFSET..INDEX_OFFSET + 4].copy_from_slice(&40u32.to_le_bytes());
        s[FEC_SET_INDEX_OFFSET..FEC_SET_INDEX_OFFSET + 4].copy_from_slice(&32u32.to_le_bytes());
        s[NUM_DATA_OFFSET..NUM_DATA_OFFSET + 2].copy_from_slice(&32u16.to_le_bytes());
        s[NUM_CODE_OFFSET..NUM_CODE_OFFSET + 2].copy_from_slice(&32u16.to_le_bytes());
        s[POSITION_OFFSET..POSITION_OFFSET + 2].copy_from_slice(&8u16.to_le_bytes());
        s
    }

    #[test]
    fn capacities_match_agave() {
        assert_eq!(DATA_CAPACITY, 963);
        assert_eq!(capacity(ShredKind::Data, 6, false), Some(963));
        assert_eq!(capacity(ShredKind::Data, 6, true), Some(899));
        assert_eq!(capacity(ShredKind::Code, 6, false), Some(987));
        assert_eq!(capacity(ShredKind::Code, 6, true), Some(923));
        // Data and code shards must be the same length for Reed-Solomon.
        assert_eq!(
            capacity(ShredKind::Data, 6, false).unwrap() + DATA_HEADERS_SIZE - SIGNATURE_SIZE,
            capacity(ShredKind::Code, 6, false).unwrap()
        );
    }

    #[test]
    fn parses_well_formed_shreds() {
        let d = Shred::parse(data_shred()).unwrap();
        assert_eq!(d.kind(), ShredKind::Data);
        assert_eq!(d.slot(), 1000);
        assert_eq!(d.index(), 35);
        assert_eq!(d.erasure_shard_index(), 3);
        assert_eq!(d.data().len(), 500 - DATA_HEADERS_SIZE);
        assert_eq!(d.parent_slot(), Some(999));
        assert_eq!(d.erasure_shard().len(), 987);

        let c = Shred::parse(code_shred()).unwrap();
        assert_eq!(c.kind(), ShredKind::Code);
        assert_eq!(c.erasure_shard_index(), 40);
        assert_eq!(c.erasure_shard().len(), 987);
    }

    #[test]
    fn repair_nonce_is_dropped() {
        let mut s = data_shred();
        s.extend_from_slice(&[1, 2, 3, 4]);
        let d = Shred::parse(s).unwrap();
        assert_eq!(d.bytes().len(), DATA_SHRED_SIZE);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(Shred::parse(vec![0; 10]), Err(ShredError::TooShort(10)));
        let mut s = data_shred();
        s[VARIANT_OFFSET] = 0xa6;
        assert_eq!(Shred::parse(s), Err(ShredError::InvalidVariant(0xa6)));
        let mut s = data_shred();
        s.truncate(1000);
        assert_eq!(Shred::parse(s), Err(ShredError::TooShort(1000)));
    }

    #[test]
    fn rejects_bad_data_headers() {
        let mut s = data_shred();
        s[INDEX_OFFSET..INDEX_OFFSET + 4].copy_from_slice(&70u32.to_le_bytes());
        assert!(matches!(
            Shred::parse(s),
            Err(ShredError::FecSetMisaligned { .. })
        ));

        let mut s = data_shred();
        s[PARENT_OFFSET_OFFSET..PARENT_OFFSET_OFFSET + 2].copy_from_slice(&0u16.to_le_bytes());
        assert!(matches!(
            Shred::parse(s),
            Err(ShredError::InvalidParentOffset { .. })
        ));

        let mut s = data_shred();
        s[FLAGS_OFFSET] = 0x80;
        assert_eq!(Shred::parse(s), Err(ShredError::InvalidFlags(0x80)));

        // last-in-slot on index 35 does not close FEC set 32..64
        let mut s = data_shred();
        s[FLAGS_OFFSET] = FLAG_LAST_IN_SLOT;
        assert_eq!(
            Shred::parse(s),
            Err(ShredError::InvalidFlags(FLAG_LAST_IN_SLOT))
        );

        let mut s = data_shred();
        s[SIZE_OFFSET..SIZE_OFFSET + 2].copy_from_slice(&(88u16 + 964).to_le_bytes());
        assert_eq!(Shred::parse(s), Err(ShredError::InvalidSize(88 + 964)));
        let mut s = data_shred();
        s[SIZE_OFFSET..SIZE_OFFSET + 2].copy_from_slice(&87u16.to_le_bytes());
        assert_eq!(Shred::parse(s), Err(ShredError::InvalidSize(87)));
    }

    #[test]
    fn rejects_bad_erasure_config() {
        let mut s = code_shred();
        s[NUM_DATA_OFFSET..NUM_DATA_OFFSET + 2].copy_from_slice(&16u16.to_le_bytes());
        assert!(matches!(
            Shred::parse(s),
            Err(ShredError::InvalidErasureConfig { .. })
        ));
        let mut s = code_shred();
        s[POSITION_OFFSET..POSITION_OFFSET + 2].copy_from_slice(&32u16.to_le_bytes());
        assert!(matches!(
            Shred::parse(s),
            Err(ShredError::InvalidErasureConfig { .. })
        ));
    }
}
