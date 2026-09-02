//! Per-stage cost of the pipeline, measured on real mainnet shreds from
//! `fixtures/mainnet.shreds`. Run with `cargo bench`.

use {
    criterion::{Criterion, Throughput, criterion_group, criterion_main},
    deshred::{
        Config, Deshredder, EntryBatch, Shred, entry,
        fec::{self, FecSet},
        fixture,
    },
    std::collections::HashMap,
};

fn packets() -> Vec<Vec<u8>> {
    fixture::Reader::open(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/mainnet.shreds"
    ))
    .expect("fixtures/mainnet.shreds")
    .map(|r| r.unwrap().packet)
    .collect()
}

fn shreds() -> Vec<Shred> {
    packets()
        .into_iter()
        .filter_map(|p| Shred::parse(p).ok())
        .collect()
}

/// Complete FEC sets (all 64 shreds) from the capture, deduplicated.
fn full_sets() -> Vec<Vec<Shred>> {
    let mut sets: HashMap<(u64, u32), Vec<Shred>> = HashMap::new();
    for shred in shreds() {
        let set = sets
            .entry((shred.slot(), shred.fec_set_index()))
            .or_default();
        if !set
            .iter()
            .any(|s: &Shred| s.is_data() == shred.is_data() && s.index() == shred.index())
        {
            set.push(shred);
        }
    }
    let mut sets: Vec<Vec<Shred>> = sets.into_values().filter(|s| s.len() == 64).collect();
    sets.truncate(16);
    assert!(!sets.is_empty(), "capture holds no complete set");
    sets
}

/// Deshredded segment payloads, rebuilt from the decoded batches. The wire
/// format round-trips, so this is byte-identical to what the pipeline decodes.
fn segments() -> Vec<Vec<u8>> {
    let mut deshredder = Deshredder::new(Config::default());
    let mut batches: Vec<EntryBatch> = Vec::new();
    for packet in packets() {
        deshredder.push(packet, &mut batches);
    }
    assert!(!batches.is_empty());
    batches
        .into_iter()
        .map(|b| entry::encode(b.entries))
        .collect()
}

fn bench_stages(c: &mut Criterion) {
    let packets = packets();
    let shreds = shreds();

    let mut group = c.benchmark_group("stages");
    group.throughput(Throughput::Elements(1));

    let mut i = 0;
    group.bench_function("parse", |b| {
        b.iter(|| {
            i = (i + 1) % packets.len();
            Shred::parse(packets[i].clone()).unwrap()
        })
    });

    let mut i = 0;
    group.bench_function("merkle_root", |b| {
        b.iter(|| {
            i = (i + 1) % shreds.len();
            shreds[i].merkle_root().unwrap()
        })
    });

    // The insert path of a whole set arriving cleanly: 32 data shreds hashed
    // and admitted, 32 code shreds dropped as unneeded.
    let sets = full_sets();
    group.throughput(Throughput::Elements(64));
    let mut i = 0;
    group.bench_function("fec_insert_full_set", |b| {
        b.iter(|| {
            i = (i + 1) % sets.len();
            let mut set = FecSet::default();
            for shred in &sets[i] {
                set.insert(shred.clone());
            }
            set
        })
    });

    // Recovery from exactly half the set: 16 data + 16 code in, 16 data out.
    group.throughput(Throughput::Elements(32));
    let rs = fec::reed_solomon();
    let mut i = 0;
    group.bench_function("fec_recover_16d_16c", |b| {
        b.iter(|| {
            i = (i + 1) % sets.len();
            let mut set = FecSet::default();
            for shred in sets[i].iter().filter(|s| s.is_data()).take(16) {
                set.insert(shred.clone());
            }
            for shred in sets[i].iter().filter(|s| !s.is_data()).take(16) {
                set.insert(shred.clone());
            }
            set.recover(&rs).unwrap()
        })
    });

    let segments = segments();
    let transactions: usize = segments
        .iter()
        .map(|s| match entry::decode(s).unwrap() {
            entry::BlockData::Entries(e) => e.iter().map(|e| e.transactions.len()).sum(),
            entry::BlockData::BlockMarker => 0,
        })
        .sum();
    group.throughput(Throughput::Elements(
        (transactions / segments.len()).max(1) as u64
    ));
    let mut i = 0;
    group.bench_function("decode_segment", |b| {
        b.iter(|| {
            i = (i + 1) % segments.len();
            entry::decode(&segments[i]).unwrap()
        })
    });

    // The zero-copy scan of the same segments: boundaries plus one field read
    // per transaction, no allocation.
    let mut i = 0;
    group.bench_function("view_segment", |b| {
        b.iter(|| {
            i = (i + 1) % segments.len();
            let mut sig_bytes = 0u64;
            for entry in deshred::view::entries(&segments[i]).unwrap() {
                for tx in entry.unwrap().transactions() {
                    sig_bytes += u64::from(tx.unwrap().signature()[0]);
                }
            }
            sig_bytes
        })
    });
    group.finish();

    let mut group = c.benchmark_group("pipeline");
    group.throughput(Throughput::Elements(packets.len() as u64));
    group.sample_size(20);
    group.bench_function("end_to_end", |b| {
        b.iter(|| {
            let mut deshredder = Deshredder::new(Config::default());
            let mut out = Vec::new();
            for packet in &packets {
                deshredder.push(packet.clone(), &mut out);
            }
            out
        })
    });

    // Raw runs plus the zero-copy scan instead of the owned decode.
    group.bench_function("end_to_end_views", |b| {
        b.iter(|| {
            let mut deshredder = Deshredder::new(Config::default());
            let mut sig_bytes = 0u64;
            for packet in &packets {
                deshredder.push_raw(packet.clone(), &mut |raw: deshred::RawBatch| {
                    let Ok(entries) = deshred::view::entries(&raw.bytes) else {
                        return;
                    };
                    for entry in entries.flatten() {
                        for tx in entry.transactions().flatten() {
                            sig_bytes += u64::from(tx.signature()[0]);
                        }
                    }
                });
            }
            sig_bytes
        })
    });
    group.finish();
}

criterion_group!(benches, bench_stages);
criterion_main!(benches);
