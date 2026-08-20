//! Counters shared between the pipeline threads and whoever wants to watch.

use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! stats {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {
        #[derive(Debug, Default)]
        pub struct Stats {
            $($(#[$doc])* pub $name: AtomicU64,)*
        }

        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
        pub struct Snapshot {
            $(pub $name: u64,)*
        }

        impl Stats {
            pub fn snapshot(&self) -> Snapshot {
                Snapshot {
                    $($name: self.$name.load(Ordering::Relaxed),)*
                }
            }
        }
    };
}

stats! {
    /// Datagrams handed to the deshredder.
    packets,
    /// Datagrams that are not a well formed shred.
    invalid,
    /// Shreds with a shred version other than the configured one.
    wrong_version,
    /// Shreds for a slot older than the retention window.
    stale,
    /// Data shreds already present, because they arrived twice or were
    /// recovered before they arrived.
    duplicates,
    /// Code shreds for FEC sets that already had all their data.
    unneeded,
    /// Shreds whose Merkle root or signature disagree with their FEC set.
    rejected,
    /// Data shreds rebuilt from code shreds.
    recovered,
    /// FEC sets where recovery failed.
    recovery_failures,
    /// Entry batches emitted.
    batches,
    /// Completed payloads that were block markers, not entries.
    block_markers,
    /// Completed payloads that did not decode.
    decode_errors,
    entries,
    transactions,
    /// Datagrams dropped because the worker thread could not keep up.
    dropped,
}

pub(crate) trait Counter {
    fn inc(&self);
    fn add(&self, n: u64);
}

impl Counter for AtomicU64 {
    #[inline]
    fn inc(&self) {
        self.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn add(&self, n: u64) {
        self.fetch_add(n, Ordering::Relaxed);
    }
}
