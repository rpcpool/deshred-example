//! Shreds in, transactions out.
//!
//! A Solana leader splits each block into shreds: ~1.2 KB UDP datagrams that
//! validators receive over turbine while the block is still being produced.
//! Receiving them directly means seeing transactions at the same time as the
//! validators, without waiting for the block to be confirmed and served
//! through RPC. This crate binds the port the shreds are sent to and hands
//! back the transactions in them:
//!
//! ```text
//! datagram -> Shred (parse, validate)            shred.rs
//!          -> FecSet (Reed-Solomon recovery)     fec.rs
//!          -> SlotState (complete data runs)     slot.rs
//!          -> Entry batch (wincode decode)       entry.rs
//!          -> EntrySink                          pipeline.rs
//! ```
//!
//! Quick start:
//!
//! ```no_run
//! use deshred::{Pipeline, PipelineConfig};
//!
//! let config = PipelineConfig::new("0.0.0.0:6767".parse().unwrap());
//! let pipeline = Pipeline::spawn(config, |batch: deshred::EntryBatch| {
//!     for entry in &batch.entries {
//!         for tx in &entry.transactions {
//!             println!("slot {} tx {}", batch.slot, tx.signatures[0]);
//!         }
//!     }
//! })
//! .unwrap();
//! std::thread::park();
//! pipeline.shutdown();
//! ```
//!
//! [`Deshredder`] is the same machinery without sockets or threads, for
//! feeding packets from anywhere (see [`fixture`] for recorded captures).
//!
//! What is deliberately not done: leader signature verification (it needs
//! the leader schedule) and PoH verification. Firewall the port to your
//! provider's source addresses.

pub mod deshredder;
pub mod entry;
pub mod fec;
pub mod fixture;
pub mod merkle;
pub mod pipeline;
pub mod shred;
pub mod slot;
pub mod socket;
pub mod stats;

pub use {
    bytes::Bytes,
    deshredder::{Config, Deshredder, EntryBatch},
    entry::Entry,
    pipeline::{ChannelSink, EntrySink, Pipeline, PipelineConfig},
    shred::Shred,
    solana_transaction::versioned::VersionedTransaction,
    stats::{Snapshot, Stats},
};
