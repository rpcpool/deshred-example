//! Per-slot assembly: FEC sets plus the bookkeeping needed to know when a run
//! of data shreds forms a complete entry batch.
//!
//! The leader serializes one `BlockComponent` (normally a `Vec<Entry>`) and
//! spreads it over consecutive data shreds; the last shred of the run has the
//! `DATA_COMPLETE` flag. A run can span several FEC sets and a set can hold
//! several runs. A run is ready when every shred from the one after the
//! previous `DATA_COMPLETE` (or index 0) up to the next `DATA_COMPLETE` is
//! present. That is the rule behind agave's completed data ranges
//! (<https://github.com/anza-xyz/agave/blob/v4.2.0/ledger/src/blockstore.rs#L5199>),
//! and it is also why it is not enough to wait for one FEC set: the batch may
//! have started in the previous one.

use {
    crate::{
        fec::{FecSet, Insert, ReedSolomon},
        shred::{DATA_CAPACITY, DATA_SHREDS_PER_FEC_SET, MAX_SHREDS_PER_SLOT, Shred},
        stats::{Counter, Stats},
    },
    fixedbitset::FixedBitSet,
    std::{collections::HashMap, ops::RangeInclusive},
};

/// The deshredded bytes of one complete run of data shreds.
pub struct Segment {
    pub shreds: RangeInclusive<u32>,
    pub bytes: Vec<u8>,
    pub last_in_slot: bool,
}

pub struct SlotState {
    sets: HashMap<u32, FecSet>,
    /// Data shred present (received or recovered).
    received: FixedBitSet,
    /// Data shred carries `DATA_COMPLETE`.
    complete: FixedBitSet,
    /// Data shred already emitted as part of a segment.
    consumed: FixedBitSet,
}

impl Default for SlotState {
    fn default() -> Self {
        let bits = MAX_SHREDS_PER_SLOT as usize;
        Self {
            sets: HashMap::new(),
            received: FixedBitSet::with_capacity(bits),
            complete: FixedBitSet::with_capacity(bits),
            consumed: FixedBitSet::with_capacity(bits),
        }
    }
}

impl SlotState {
    /// Add a shred, run recovery if it became possible, and push every
    /// segment that is now complete onto `out`.
    pub fn insert(
        &mut self,
        shred: Shred,
        rs: Option<&ReedSolomon>,
        stats: &Stats,
        out: &mut Vec<Segment>,
    ) {
        let fec_set_index = shred.fec_set_index();
        let index = shred.index();
        let is_data = shred.is_data();
        if is_data && self.received.contains(index as usize) {
            stats.duplicates.inc();
            return;
        }
        if !is_data && self.set_is_consumed(fec_set_index) {
            stats.unneeded.inc();
            return;
        }

        // Indexes that became available with this packet, at most a whole set.
        let mut fresh = [0u32; DATA_SHREDS_PER_FEC_SET];
        let mut num_fresh = 0;

        let set = self.sets.entry(fec_set_index).or_default();
        match set.insert(shred) {
            Insert::New => {}
            Insert::Duplicate => {
                stats.duplicates.inc();
                return;
            }
            Insert::Unneeded => {
                stats.unneeded.inc();
                return;
            }
            Insert::Rejected(why) => {
                log::debug!("rejected shred index {index} of fec set {fec_set_index}: {why:?}");
                stats.rejected.inc();
                return;
            }
        }
        if is_data {
            fresh[num_fresh] = index;
            num_fresh += 1;
        }
        if let Some(rs) = rs
            && set.can_recover()
        {
            match set.recover(rs) {
                Ok(indexes) => {
                    stats.recovered.add(indexes.len() as u64);
                    for i in indexes {
                        fresh[num_fresh] = i;
                        num_fresh += 1;
                    }
                }
                Err(err) => {
                    log::warn!("recovery failed for fec set {fec_set_index}: {err}");
                    stats.recovery_failures.inc();
                }
            }
        }
        for &i in &fresh[..num_fresh] {
            let shred = set.data((i - fec_set_index) as usize).unwrap();
            self.received.insert(i as usize);
            if shred.data_complete() {
                self.complete.insert(i as usize);
            }
        }
        for &i in &fresh[..num_fresh] {
            self.try_complete(i, out);
            // The run after a DATA_COMPLETE shred may have been waiting only
            // for this boundary to become known.
            if self.complete.contains(i as usize) {
                self.try_complete(i + 1, out);
            }
        }
    }

    fn set_is_consumed(&self, fec_set_index: u32) -> bool {
        let start = fec_set_index as usize;
        self.consumed
            .count_ones(start..start + DATA_SHREDS_PER_FEC_SET)
            == DATA_SHREDS_PER_FEC_SET
    }

    /// Bounds of the run containing `index`, if every shred in it is present.
    fn find_segment(&self, index: u32) -> Option<(u32, u32)> {
        let mut end = index as usize;
        loop {
            if !self.received.contains(end) {
                return None;
            }
            if self.complete.contains(end) {
                break;
            }
            end += 1;
            if end >= MAX_SHREDS_PER_SLOT as usize {
                return None;
            }
        }
        let mut start = index as usize;
        while start > 0 && !self.complete.contains(start - 1) {
            if !self.received.contains(start - 1) {
                return None;
            }
            start -= 1;
        }
        Some((start as u32, end as u32))
    }

    fn data(&self, index: u32) -> &Shred {
        let fec_set_index = index - index % DATA_SHREDS_PER_FEC_SET as u32;
        self.sets[&fec_set_index]
            .data((index - fec_set_index) as usize)
            .expect("received bit set without shred")
    }

    fn try_complete(&mut self, index: u32, out: &mut Vec<Segment>) {
        if index >= MAX_SHREDS_PER_SLOT || self.consumed.contains(index as usize) {
            return;
        }
        let Some((start, end)) = self.find_segment(index) else {
            return;
        };
        let mut bytes = Vec::with_capacity((end - start + 1) as usize * DATA_CAPACITY);
        for i in start..=end {
            bytes.extend_from_slice(self.data(i).data());
        }
        let last_in_slot = self.data(end).last_in_slot();
        self.consumed.insert_range(start as usize..end as usize + 1);
        out.push(Segment {
            shreds: start..=end,
            bytes,
            last_in_slot,
        });

        // Free sets that have nothing left to give.
        let first_set = start - start % DATA_SHREDS_PER_FEC_SET as u32;
        for fec_set_index in (first_set..=end).step_by(DATA_SHREDS_PER_FEC_SET) {
            if self.set_is_consumed(fec_set_index) {
                self.sets.remove(&fec_set_index);
            }
        }
    }
}
