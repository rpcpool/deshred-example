//! Is eager recovery worth it? Replays a capture's receive timestamps and,
//! for every FEC set, measures the gap between the moment recovery became
//! possible (32 distinct shreds, at least one of them code) and the moment
//! the last data shred actually arrived. That gap is the latency eager
//! recovery saves; its price is the reconstruction cost (`cargo bench`,
//! `fec_recover_*`).

use {
    clap::Parser,
    deshred::{Config, Deshredder, EntryBatch, Shred, fixture, shred::DATA_SHREDS_PER_FEC_SET},
    std::{collections::HashMap, path::PathBuf},
};

/// Measured reconstruction cost on the reference machine (`cargo bench`,
/// `fec_recover_16d_16c`). Charged to every batch the eager policy emitted
/// from a push that ran a recovery.
const RECOVERY_COST_US: u64 = 46;

#[derive(Parser)]
#[command(about = "Measure what eager FEC recovery saves on a recorded capture")]
struct Cli {
    /// Capture recorded with `deshred listen --record`.
    file: PathBuf,
}

#[derive(Default)]
struct SetState {
    /// Receive time of the nth distinct shred, in capture order.
    arrivals: Vec<u64>,
    seen_data: [bool; DATA_SHREDS_PER_FEC_SET],
    seen_code: [bool; DATA_SHREDS_PER_FEC_SET],
    num_data: usize,
    first_code_at: Option<u64>,
    /// When the 32nd data shred arrived.
    data_complete_at: Option<u64>,
    /// When 32 distinct shreds were present.
    threshold_at: Option<u64>,
    /// Data shreds still missing when the threshold was reached.
    missing_at_threshold: usize,
}

fn percentile(sorted: &[u64], p: usize) -> u64 {
    sorted[(p * sorted.len()).saturating_sub(1) / 100]
}

fn print_distribution(name: &str, mut values: Vec<u64>) {
    if values.is_empty() {
        println!("{name}: no samples");
        return;
    }
    values.sort_unstable();
    let mean = values.iter().sum::<u64>() / values.len() as u64;
    println!(
        "{name}: n {} | mean {} | p50 {} | p90 {} | p99 {} | max {}",
        values.len(),
        mean,
        percentile(&values, 50),
        percentile(&values, 90),
        percentile(&values, 99),
        values[values.len() - 1],
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut sets: HashMap<(u64, u32), SetState> = HashMap::new();
    let mut packets = 0usize;

    for record in fixture::Reader::open(&cli.file)? {
        let record = record?;
        packets += 1;
        let Ok(shred) = Shred::parse(record.packet) else {
            continue;
        };
        let state = sets
            .entry((shred.slot(), shred.fec_set_index()))
            .or_default();
        let position = shred.erasure_shard_index() % DATA_SHREDS_PER_FEC_SET;
        let seen = if shred.is_data() {
            &mut state.seen_data[position]
        } else {
            &mut state.seen_code[position]
        };
        if *seen {
            continue;
        }
        *seen = true;
        state.arrivals.push(record.unix_nanos);
        if shred.is_data() {
            state.num_data += 1;
            if state.num_data == DATA_SHREDS_PER_FEC_SET {
                state.data_complete_at = Some(record.unix_nanos);
            }
        } else if state.first_code_at.is_none() {
            state.first_code_at = Some(record.unix_nanos);
        }
        if state.arrivals.len() == DATA_SHREDS_PER_FEC_SET && state.first_code_at.is_some() {
            state.threshold_at = Some(record.unix_nanos);
            state.missing_at_threshold = DATA_SHREDS_PER_FEC_SET - state.num_data;
        }
    }

    let total = sets.len();
    let mut wait_us = Vec::new();
    let mut span_us = Vec::new();
    let mut missing = Vec::new();
    let mut data_first = 0usize;
    let mut never_complete = 0usize;
    let mut never_recoverable = 0usize;
    for state in sets.values() {
        if let (Some(first), Some(last)) = (state.arrivals.first(), state.arrivals.last()) {
            span_us.push((last - first) / 1_000);
        }
        match (state.threshold_at, state.data_complete_at) {
            (Some(threshold), Some(complete)) => {
                if state.missing_at_threshold == 0 {
                    // The 32 data shreds were the first 32 to arrive; recovery
                    // never had a window.
                    data_first += 1;
                } else {
                    wait_us.push(complete.saturating_sub(threshold) / 1_000);
                    missing.push(state.missing_at_threshold as u64);
                }
            }
            (Some(_), None) => never_complete += 1,
            (None, Some(_)) => data_first += 1,
            (None, None) => never_recoverable += 1,
        }
    }

    println!("{packets} packets, {total} FEC sets");
    println!(
        "sets where the data completed before recovery was possible: {data_first} ({:.1}%)",
        data_first as f64 * 100.0 / total as f64
    );
    println!(
        "sets where eager recovery had a window (32 shreds before the data): {} ({:.1}%)",
        wait_us.len(),
        wait_us.len() as f64 * 100.0 / total as f64
    );
    println!(
        "sets where the data never completed (recovery required): {never_complete} ({:.1}%)",
        never_complete as f64 * 100.0 / total as f64
    );
    println!("sets that never became recoverable at all: {never_recoverable}");
    println!();
    print_distribution(
        "eager recovery saves (us waited for the last data shred)",
        wait_us.clone(),
    );
    print_distribution("data shreds reconstructed when eager", missing);
    print_distribution("whole set arrival span (us)", span_us);

    transaction_latency(&cli)?;

    // Policy sweep: recover only after the set has been recoverable for a
    // grace period without completing. Skipping a recovery saves its CPU
    // cost; every set that still needs one is delivered `grace` later than
    // the eager policy would have.
    println!();
    println!("grace_us | recoveries skipped | still recovered | added latency to those");
    for grace in [0u64, 25, 50, 100, 250, 500, 1000] {
        let skipped = wait_us.iter().filter(|&&w| w <= grace).count();
        println!(
            "{grace:>8} | {:>10} ({:>5.1}%) | {:>15} | {grace} us",
            skipped,
            skipped as f64 * 100.0 / wait_us.len() as f64,
            wait_us.len() - skipped,
        );
    }
    Ok(())
}

/// Batch availability time (nanos) and transaction count, keyed by slot and
/// first shred index.
type BatchTimes = HashMap<(u64, u32), (u64, u64)>;

/// When did each batch's transactions become available under a policy?
/// Batches are keyed by their shred range, which does not depend on the
/// policy. The timestamp is the receive time of the packet whose processing
/// emitted the batch, plus the reconstruction cost when that packet
/// triggered a recovery.
fn batch_times(file: &PathBuf, recover: bool) -> Result<BatchTimes, Box<dyn std::error::Error>> {
    let mut deshredder = Deshredder::new(Config {
        recover,
        ..Config::default()
    });
    let mut times = HashMap::new();
    let mut out: Vec<EntryBatch> = Vec::new();
    let mut recoveries = 0;
    for record in fixture::Reader::open(file)? {
        let record = record?;
        deshredder.push(record.packet, &mut out);
        let recovered = deshredder.stats().snapshot().recovered;
        let cost = if recovered > recoveries {
            RECOVERY_COST_US * 1_000
        } else {
            0
        };
        recoveries = recovered;
        for batch in out.drain(..) {
            times.insert(
                (batch.slot, *batch.shreds.start()),
                (record.unix_nanos + cost, batch.num_transactions() as u64),
            );
        }
    }
    Ok(times)
}

fn transaction_latency(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let eager = batch_times(&cli.file, true)?;
    let waiting = batch_times(&cli.file, false)?;

    let mut deltas = Vec::new();
    let mut ties = 0u64;
    let mut only_with_recovery = 0u64;
    let mut total = 0u64;
    for (key, &(eager_at, txs)) in &eager {
        total += txs;
        match waiting.get(key) {
            Some(&(waiting_at, _)) => {
                let delta = waiting_at.saturating_sub(eager_at) / 1_000;
                if delta == 0 {
                    ties += txs;
                } else {
                    deltas.extend(std::iter::repeat_n(delta, txs as usize));
                }
            }
            None => only_with_recovery += txs,
        }
    }

    println!();
    println!("transaction latency, eager recovery vs waiting for the data shreds:");
    println!(
        "  {total} transactions | unaffected {ties} ({:.1}%) | faster with recovery {} ({:.1}%) | only delivered thanks to recovery {only_with_recovery} ({:.1}%)",
        ties as f64 * 100.0 / total as f64,
        deltas.len(),
        deltas.len() as f64 * 100.0 / total as f64,
        only_with_recovery as f64 * 100.0 / total as f64,
    );
    print_distribution(
        "  us earlier per accelerated transaction (46us recovery cost included)",
        deltas,
    );
    Ok(())
}
