//! Replays every capture in `fixtures/*.shreds` (recorded from a live port
//! with `deshred listen --record`). The clean replay is the reference; the
//! same capture degraded by loss, reordering, duplication and corruption has
//! to produce the same entries. Without captures these tests have nothing to
//! check and pass after printing a notice.

use {
    deshred::{Config, Deshredder, Entry, EntryBatch, Shred, fixture},
    std::{collections::HashMap, path::PathBuf},
};

const LOOKBACK: u64 = 64;

struct Capture {
    name: String,
    packets: Vec<Vec<u8>>,
    shred_version: u16,
}

fn captures() -> Vec<Capture> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let mut captures = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "shreds") {
            continue;
        }
        let packets: Vec<Vec<u8>> = fixture::Reader::open(&path)
            .unwrap()
            .map(|r| r.unwrap().packet)
            .collect();
        let shred_version = packets
            .iter()
            .find_map(|p| Shred::parse(p.clone()).ok())
            .expect("capture holds at least one valid shred")
            .version();
        captures.push(Capture {
            name: path.file_name().unwrap().to_string_lossy().into_owned(),
            packets,
            shred_version,
        });
    }
    if captures.is_empty() {
        eprintln!(
            "no captures in {}: record one with `deshred listen --record fixtures/<name>.shreds`",
            dir.display()
        );
    }
    captures
}

fn deshredder(shred_version: u16) -> Deshredder {
    Deshredder::new(Config {
        shred_version: Some(shred_version),
        slot_lookback: LOOKBACK,
    })
}

fn feed(
    deshredder: &mut Deshredder,
    packets: impl IntoIterator<Item = Vec<u8>>,
) -> Vec<EntryBatch> {
    let mut out = Vec::new();
    for packet in packets {
        deshredder.push(packet, &mut out);
    }
    out
}

/// Entries per slot, in shred order.
fn by_slot(batches: &[EntryBatch]) -> HashMap<u64, Vec<Entry>> {
    let mut sorted: Vec<&EntryBatch> = batches.iter().collect();
    sorted.sort_by_key(|b| (b.slot, *b.shreds.start()));
    let mut out: HashMap<u64, Vec<Entry>> = HashMap::new();
    for b in sorted {
        out.entry(b.slot)
            .or_default()
            .extend(b.entries.iter().cloned());
    }
    out
}

/// Deterministic shuffle without a rand dependency.
fn shuffle<T>(items: &mut [T], mut seed: u64) {
    for i in (1..items.len()).rev() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        items.swap(i, (seed % (i as u64 + 1)) as usize);
    }
}

/// Packets grouped by FEC set, in capture order, without the duplicates a
/// live capture contains (the same datagram can arrive on two paths).
fn sets(packets: &[Vec<u8>]) -> Vec<Vec<Vec<u8>>> {
    let mut index: HashMap<(u64, u32), usize> = HashMap::new();
    let mut seen: std::collections::HashSet<(u64, bool, u32)> = std::collections::HashSet::new();
    let mut sets: Vec<Vec<Vec<u8>>> = Vec::new();
    for p in packets {
        let Ok(shred) = Shred::parse(p.clone()) else {
            continue;
        };
        if !seen.insert((shred.slot(), shred.is_data(), shred.index())) {
            continue;
        }
        let key = (shred.slot(), shred.fec_set_index());
        let i = *index.entry(key).or_insert_with(|| {
            sets.push(Vec::new());
            sets.len() - 1
        });
        sets[i].push(p.clone());
    }
    sets
}

fn reference(capture: &Capture) -> (Vec<EntryBatch>, deshred::Snapshot) {
    let mut d = deshredder(capture.shred_version);
    let batches = feed(&mut d, capture.packets.clone());
    (batches, d.stats().snapshot())
}

#[test]
fn clean_replay_decodes_everything() {
    for capture in captures() {
        let (batches, s) = reference(&capture);
        eprintln!("{}: {s:?}", capture.name);
        assert!(s.batches > 0, "{}: nothing decoded", capture.name);
        assert!(s.transactions > 0, "{}: no transactions", capture.name);
        assert_eq!(s.invalid, 0, "{}: malformed packets", capture.name);
        assert_eq!(s.rejected, 0, "{}: merkle mismatches", capture.name);
        assert_eq!(s.decode_errors, 0, "{}: undecodable runs", capture.name);
        assert_eq!(s.recovery_failures, 0, "{}", capture.name);
        assert!(
            batches.iter().any(|b| b.last_in_slot),
            "{}: no slot end seen",
            capture.name
        );
        for b in &batches {
            for tx in b.entries.iter().flat_map(|e| &e.transactions) {
                assert!(!tx.signatures.is_empty());
            }
        }
    }
}

#[test]
fn shuffled_replay_matches_reference() {
    for capture in captures() {
        let (batches, _) = reference(&capture);
        let mut packets = capture.packets.clone();
        shuffle(&mut packets, 99);
        let mut d = deshredder(capture.shred_version);
        let shuffled = feed(&mut d, packets);
        assert_eq!(by_slot(&shuffled), by_slot(&batches), "{}", capture.name);
        assert_eq!(d.stats().snapshot().decode_errors, 0);
    }
}

#[test]
fn half_of_each_set_is_enough() {
    for capture in captures() {
        let (batches, _) = reference(&capture);
        // Keep 32 random shreds of every set that has at least that many;
        // sets that were already short in the capture stay as they were.
        let mut kept = Vec::new();
        for (i, mut set) in sets(&capture.packets).into_iter().enumerate() {
            if set.len() > 32 {
                shuffle(&mut set, 1000 + i as u64);
                set.truncate(32);
            }
            kept.extend(set);
        }
        let mut d = deshredder(capture.shred_version);
        let lossy = feed(&mut d, kept);
        let s = d.stats().snapshot();
        assert!(s.recovered > 0, "{}", capture.name);
        assert_eq!(s.recovery_failures, 0, "{}", capture.name);
        assert_eq!(by_slot(&lossy), by_slot(&batches), "{}", capture.name);
    }
}

#[test]
fn corrupted_shreds_are_rejected_and_recovered() {
    for capture in captures() {
        let (batches, _) = reference(&capture);
        // Corrupt one data shred per set that is not the first of its set to
        // arrive (the first one defines the set's Merkle root) and still
        // leaves 32 good shreds behind.
        let mut packets = capture.packets.clone();
        let mut seen: HashMap<(u64, u32), usize> = HashMap::new();
        let sizes: HashMap<(u64, u32), usize> = sets(&capture.packets)
            .iter()
            .filter_map(|set| {
                let s = Shred::parse(set[0].clone()).ok()?;
                Some(((s.slot(), s.fec_set_index()), set.len()))
            })
            .collect();
        let mut corrupted = 0;
        for p in packets.iter_mut() {
            let Ok(shred) = Shred::parse(p.clone()) else {
                continue;
            };
            let key = (shred.slot(), shred.fec_set_index());
            let n = seen.entry(key).or_insert(0);
            *n += 1;
            if *n == 2 && shred.is_data() && sizes[&key] >= 33 {
                p[200] ^= 0xff;
                corrupted += 1;
            }
        }
        assert!(corrupted > 0, "{}", capture.name);
        let mut d = deshredder(capture.shred_version);
        let result = feed(&mut d, packets);
        let s = d.stats().snapshot();
        assert_eq!(s.rejected, corrupted, "{}", capture.name);
        assert!(s.recovered >= corrupted, "{}", capture.name);
        assert_eq!(by_slot(&result), by_slot(&batches), "{}", capture.name);
    }
}

#[test]
fn duplicates_do_not_double_emit() {
    for capture in captures() {
        let (batches, _) = reference(&capture);
        let mut packets = capture.packets.clone();
        packets.extend(capture.packets.clone());
        let mut d = deshredder(capture.shred_version);
        let doubled = feed(&mut d, packets);
        assert_eq!(doubled.len(), batches.len(), "{}", capture.name);
        assert_eq!(by_slot(&doubled), by_slot(&batches), "{}", capture.name);
        let s = d.stats().snapshot();
        assert!(s.duplicates > 0 && s.unneeded > 0, "{}", capture.name);
    }
}

#[test]
fn wrong_shred_version_is_dropped() {
    for capture in captures() {
        let mut d = deshredder(capture.shred_version.wrapping_add(1));
        assert!(feed(&mut d, capture.packets.clone()).is_empty());
        let s = d.stats().snapshot();
        assert_eq!(s.wrong_version + s.invalid, capture.packets.len() as u64);
    }
}

#[test]
fn garbage_is_counted_not_emitted() {
    let mut d = deshredder(0);
    let junk = vec![vec![0xffu8; 1203], b"hello".to_vec(), vec![0u8; 1228]];
    assert!(feed(&mut d, junk).is_empty());
    assert_eq!(d.stats().snapshot().invalid, 3);
}
