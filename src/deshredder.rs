//! The sans-IO core: feed it datagrams, get entry batches back.
//!
//! No sockets or threads here, so the same code runs against a live port
//! (see [`crate::pipeline`]) or a recorded fixture (see [`crate::fixture`]).

use {
    crate::{
        entry::{self, BlockData, Entry},
        fec::{self, ReedSolomon},
        shred::Shred,
        slot::{Segment, SlotState},
        stats::{Counter, Stats},
    },
    std::{collections::BTreeMap, ops::RangeInclusive, sync::Arc},
};

#[derive(Debug, Clone)]
pub struct Config {
    /// Drop shreds whose version differs. `None` accepts any version; set it
    /// once you know the cluster's (`solana gossip` or the RPC
    /// `getVersion`/`getGenesisHash` mapping) so misrouted traffic is dropped.
    pub shred_version: Option<u16>,
    /// Slots older than `highest_seen - slot_lookback` are dropped and their
    /// state freed. Shreds for one slot arrive over ~400ms, so anything past
    /// a few dozen slots is never going to complete.
    pub slot_lookback: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            shred_version: None,
            slot_lookback: 64,
        }
    }
}

/// One deshredded run of data shreds, not yet decoded. Feed the bytes to
/// [`crate::view::entries`] for the zero-copy path or to
/// [`crate::entry::decode`] for owned entries.
#[derive(Debug, Clone)]
pub struct RawBatch {
    pub slot: u64,
    /// Data shred indexes this batch was assembled from.
    pub shreds: RangeInclusive<u32>,
    /// The last shred of the batch carried `LAST_SHRED_IN_SLOT`.
    pub last_in_slot: bool,
    /// The concatenated shred payloads: one serialized block component.
    pub bytes: Vec<u8>,
}

/// One deshredded `Vec<Entry>` with its position in the slot.
#[derive(Debug, Clone)]
pub struct EntryBatch {
    pub slot: u64,
    /// Data shred indexes this batch was assembled from.
    pub shreds: RangeInclusive<u32>,
    /// The last shred of the batch carried `LAST_SHRED_IN_SLOT`.
    pub last_in_slot: bool,
    pub entries: Vec<Entry>,
}

impl EntryBatch {
    pub fn num_transactions(&self) -> usize {
        self.entries.iter().map(|e| e.transactions.len()).sum()
    }
}

pub struct Deshredder {
    config: Config,
    slots: BTreeMap<u64, SlotState>,
    highest_slot: u64,
    rs: ReedSolomon,
    stats: Arc<Stats>,
    segments: Vec<Segment>,
}

impl Deshredder {
    pub fn new(config: Config) -> Self {
        Self::with_stats(config, Arc::default())
    }

    pub fn with_stats(config: Config, stats: Arc<Stats>) -> Self {
        Self {
            config,
            slots: BTreeMap::new(),
            highest_slot: 0,
            rs: fec::reed_solomon(),
            stats,
            segments: Vec::new(),
        }
    }

    pub const fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    /// Process one datagram. Completed batches are appended to `out` decoded;
    /// a single packet can complete several (it may finish a pending FEC
    /// set).
    pub fn push(&mut self, packet: impl Into<bytes::Bytes>, out: &mut Vec<EntryBatch>) {
        let stats = Arc::clone(&self.stats);
        self.push_raw(
            packet,
            &mut |raw: RawBatch| match entry::decode(&raw.bytes) {
                Ok(BlockData::Entries(entries)) => {
                    stats.entries.add(entries.len() as u64);
                    stats
                        .transactions
                        .add(entries.iter().map(|e| e.transactions.len() as u64).sum());
                    out.push(EntryBatch {
                        slot: raw.slot,
                        shreds: raw.shreds,
                        last_in_slot: raw.last_in_slot,
                        entries,
                    });
                }
                Ok(BlockData::BlockMarker) => stats.block_markers.inc(),
                Err(err) => {
                    log::warn!(
                        "slot {} shreds {:?}: cannot decode {} bytes: {err}",
                        raw.slot,
                        raw.shreds,
                        raw.bytes.len()
                    );
                    stats.decode_errors.inc();
                }
            },
        );
    }

    /// Like [`Deshredder::push`], but hands out the undecoded runs. The
    /// zero-copy path: nothing beyond the run assembly is allocated, decode
    /// however much you need with [`crate::view`]. Block markers (a run whose
    /// bytes begin with eight zero bytes) are handed out too.
    pub fn push_raw(&mut self, packet: impl Into<bytes::Bytes>, out: &mut impl FnMut(RawBatch)) {
        let Self {
            config,
            slots,
            highest_slot,
            rs,
            stats,
            segments,
        } = self;
        stats.packets.inc();

        let shred = match Shred::parse(packet) {
            Ok(shred) => shred,
            Err(err) => {
                log::debug!("invalid shred: {err}");
                stats.invalid.inc();
                return;
            }
        };
        if config.shred_version.is_some_and(|v| v != shred.version()) {
            stats.wrong_version.inc();
            return;
        }
        let slot = shred.slot();
        if slot + config.slot_lookback < *highest_slot {
            stats.stale.inc();
            return;
        }

        segments.clear();
        slots
            .entry(slot)
            .or_default()
            .insert(shred, rs, stats, segments);

        if !segments.is_empty() && slot > *highest_slot {
            // Only a slot that produced a complete run moves the window. A
            // single packet with a bogus slot number would otherwise make
            // every real slot look stale; faking a whole consistent FEC set
            // is a much higher bar (leader sigverify would close it fully).
            *highest_slot = slot;
            while let Some((&oldest, _)) = slots.first_key_value() {
                if oldest + config.slot_lookback >= slot {
                    break;
                }
                slots.pop_first();
            }
        }
        // Bound memory if garbage keeps creating far-future slots.
        while slots.len() > 4 * config.slot_lookback as usize {
            slots.pop_last();
        }

        for segment in segments.drain(..) {
            stats.batches.inc();
            out(RawBatch {
                slot,
                shreds: segment.shreds,
                last_in_slot: segment.last_in_slot,
                bytes: segment.bytes,
            });
        }
    }
}
