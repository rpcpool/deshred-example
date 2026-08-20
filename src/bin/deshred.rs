//! Command line front end: listen on a port, or replay a recorded fixture,
//! and print what comes out.

use {
    clap::{Parser, Subcommand, ValueEnum},
    deshred::{Config, Deshredder, EntryBatch, Pipeline, PipelineConfig, Stats, fixture},
    std::{
        net::SocketAddr,
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    },
};

#[derive(Parser)]
#[command(about = "Turn Solana shreds into transactions")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bind a UDP port and print the transactions found in incoming shreds.
    Listen {
        /// Address and port the shreds are sent to.
        #[arg(long, default_value = "0.0.0.0:6767")]
        bind: SocketAddr,
        /// Drop shreds from other clusters. Leave unset to accept any.
        #[arg(long)]
        shred_version: Option<u16>,
        /// Kernel receive buffer in MiB.
        #[arg(long, default_value_t = 64)]
        rcvbuf_mib: usize,
        /// Also write every received datagram to this fixture file.
        #[arg(long)]
        record: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Print::Batches)]
        print: Print,
        /// Seconds between stats lines (0 disables).
        #[arg(long, default_value_t = 5)]
        stats_every: u64,
    },
    /// Feed a recorded fixture through the deshredder.
    Replay {
        file: PathBuf,
        #[arg(long)]
        shred_version: Option<u16>,
        #[arg(long, value_enum, default_value_t = Print::Batches)]
        print: Print,
    },
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
enum Print {
    /// One line per entry batch.
    Batches,
    /// One line per transaction.
    Transactions,
    None,
}

fn print_batch(print: Print, batch: &EntryBatch) {
    if print == Print::None {
        return;
    }
    println!(
        "slot {} shreds {}..={} entries {} txs {}{}",
        batch.slot,
        batch.shreds.start(),
        batch.shreds.end(),
        batch.entries.len(),
        batch.num_transactions(),
        if batch.last_in_slot {
            " (last in slot)"
        } else {
            ""
        }
    );
    if print == Print::Transactions {
        for entry in &batch.entries {
            for tx in &entry.transactions {
                let signature = tx
                    .signatures
                    .first()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                println!("  {:?} {signature}", tx.version());
            }
        }
    }
}

fn print_stats(stats: &Stats) {
    let s = stats.snapshot();
    println!(
        "stats: packets {} invalid {} wrong_version {} stale {} dup {} unneeded {} rejected {} recovered {} \
         recovery_failures {} batches {} markers {} decode_errors {} entries {} txs {} dropped {}",
        s.packets,
        s.invalid,
        s.wrong_version,
        s.stale,
        s.duplicates,
        s.unneeded,
        s.rejected,
        s.recovered,
        s.recovery_failures,
        s.batches,
        s.block_markers,
        s.decode_errors,
        s.entries,
        s.transactions,
        s.dropped
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match Cli::parse().command {
        Command::Listen {
            bind,
            shred_version,
            rcvbuf_mib,
            record,
            print,
            stats_every,
        } => {
            let mut config = PipelineConfig::new(bind);
            config.recv_buffer_bytes = rcvbuf_mib << 20;
            config.deshredder.shred_version = shred_version;

            let tap = match record {
                Some(path) => {
                    let mut writer = fixture::Writer::create(&path)?;
                    log::info!("recording datagrams to {}", path.display());
                    Some(Box::new(move |packet: &[u8]| {
                        if let Err(err) = writer.write(packet) {
                            log::error!("record failed: {err}");
                        }
                    }) as deshred::pipeline::PacketTap)
                }
                None => None,
            };

            let pipeline = Pipeline::spawn_with_tap(
                config,
                move |batch: EntryBatch| print_batch(print, &batch),
                tap,
            )?;

            let stop = Arc::new(AtomicBool::new(false));
            ctrlc::set_handler({
                let stop = Arc::clone(&stop);
                move || stop.store(true, Ordering::Relaxed)
            })?;
            let mut since_stats = Duration::ZERO;
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(200));
                since_stats += Duration::from_millis(200);
                if stats_every > 0 && since_stats >= Duration::from_secs(stats_every) {
                    print_stats(pipeline.stats());
                    since_stats = Duration::ZERO;
                }
            }
            print_stats(pipeline.stats());
            // Drops the tap, which flushes the fixture writer.
            pipeline.shutdown();
        }
        Command::Replay {
            file,
            shred_version,
            print,
        } => {
            let config = Config {
                shred_version,
                ..Config::default()
            };
            let mut deshredder = Deshredder::new(config);
            let reader = fixture::Reader::open(&file)?;
            let packets =
                fixture::replay(reader, &mut deshredder, &mut move |batch: EntryBatch| {
                    print_batch(print, &batch)
                })?;
            println!("replayed {packets} packets from {}", file.display());
            print_stats(deshredder.stats());
        }
    }
    Ok(())
}
