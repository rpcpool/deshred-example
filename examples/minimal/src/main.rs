//! The smallest useful program: bind the port, print every transaction.
//!
//! cargo run --release -p deshred-minimal -- 0.0.0.0:20000

use deshred::{EntryBatch, Pipeline, PipelineConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:20000".into());
    let config = PipelineConfig::new(bind.parse()?);

    let pipeline = Pipeline::spawn(config, |batch: EntryBatch| {
        for entry in &batch.entries {
            for tx in &entry.transactions {
                // Everything a strategy needs is in `tx.message`: accounts,
                // instructions, program ids. Here we just print the id.
                println!(
                    "slot {} {:?} {}",
                    batch.slot,
                    tx.version(),
                    tx.signatures[0]
                );
            }
        }
    })?;

    std::thread::park();
    pipeline.shutdown();
    Ok(())
}
