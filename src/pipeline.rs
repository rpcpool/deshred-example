//! Socket to sink: the two threads that turn a bound port into a stream of
//! entry batches.
//!
//! ```text
//! UDP port --recv--> receiver thread --channel--> worker thread --> EntrySink
//!                                                   (Deshredder)
//! ```
//!
//! The receiver does nothing but pull datagrams off the socket (in batches,
//! see [`crate::socket::Receiver`]), so the kernel buffer is drained even
//! while the worker is busy recovering a FEC set or while the sink is slow.
//! If the channel fills up, packets are dropped and counted in
//! `Stats::dropped` rather than silently lost in the kernel. Packets cross
//! the channel as `Bytes` slices of the receive buffer: no copy, no
//! per-packet allocation.

use {
    crate::{
        deshredder::{Config, Deshredder, EntryBatch},
        socket,
        stats::{Counter, Stats},
    },
    bytes::Bytes,
    crossbeam_channel::{Receiver, Sender, TrySendError},
    std::{
        io,
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread::JoinHandle,
        time::Duration,
    },
};

/// Receives every entry batch, in the order they complete.
pub trait EntrySink: Send {
    fn on_batch(&mut self, batch: EntryBatch);
}

impl<F: FnMut(EntryBatch) + Send> EntrySink for F {
    fn on_batch(&mut self, batch: EntryBatch) {
        self(batch)
    }
}

/// Sink that forwards batches to a channel, for consumers that want to pull.
pub struct ChannelSink(Sender<EntryBatch>);

impl ChannelSink {
    pub fn new(capacity: usize) -> (Self, Receiver<EntryBatch>) {
        let (tx, rx) = crossbeam_channel::bounded(capacity);
        (Self(tx), rx)
    }
}

impl EntrySink for ChannelSink {
    fn on_batch(&mut self, batch: EntryBatch) {
        // A closed receiver means the consumer is gone; nothing to do.
        let _ = self.0.send(batch);
    }
}

/// Called with every raw datagram before it is deshredded.
pub type PacketTap = Box<dyn FnMut(&[u8]) + Send>;

#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Address to bind, e.g. `0.0.0.0:6767`. Shreds are sent to this port.
    pub bind: SocketAddr,
    /// Kernel receive buffer size.
    pub recv_buffer_bytes: usize,
    /// Datagrams buffered between the receiver and worker threads.
    pub channel_capacity: usize,
    pub deshredder: Config,
}

impl PipelineConfig {
    pub fn new(bind: SocketAddr) -> Self {
        Self {
            bind,
            recv_buffer_bytes: 64 << 20,
            channel_capacity: 1 << 16,
            deshredder: Config::default(),
        }
    }
}

pub struct Pipeline {
    stats: Arc<Stats>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Pipeline {
    /// Bind the port and start both threads.
    pub fn spawn(config: PipelineConfig, sink: impl EntrySink + 'static) -> io::Result<Self> {
        Self::spawn_with_tap(config, sink, None)
    }

    /// Same as [`Pipeline::spawn`], with a hook that sees every datagram
    /// (used to record fixtures).
    pub fn spawn_with_tap(
        config: PipelineConfig,
        mut sink: impl EntrySink + 'static,
        mut tap: Option<PacketTap>,
    ) -> io::Result<Self> {
        let socket = socket::bind(config.bind, config.recv_buffer_bytes)?;
        // Wake up periodically so the receiver notices a shutdown request.
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        log::info!("listening for shreds on {}", socket.local_addr()?);

        let stats = Arc::new(Stats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = crossbeam_channel::bounded::<Bytes>(config.channel_capacity);

        let receiver = std::thread::Builder::new().name("shred-rx".into()).spawn({
            let stats = Arc::clone(&stats);
            let stop = Arc::clone(&stop);
            move || receive_loop(&mut socket::Receiver::new(socket), &tx, &stats, &stop)
        })?;

        let worker = std::thread::Builder::new().name("deshred".into()).spawn({
            let mut deshredder = Deshredder::with_stats(config.deshredder, Arc::clone(&stats));
            move || {
                let mut out = Vec::new();
                for packet in rx {
                    if let Some(tap) = tap.as_mut() {
                        tap(&packet);
                    }
                    deshredder.push(packet, &mut out);
                    for batch in out.drain(..) {
                        sink.on_batch(batch);
                    }
                }
            }
        })?;

        Ok(Self {
            stats,
            stop,
            threads: vec![receiver, worker],
        })
    }

    pub const fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    /// Stop receiving, drain what is buffered, and wait for both threads.
    pub fn shutdown(self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}

fn receive_loop(
    receiver: &mut socket::Receiver,
    tx: &Sender<Bytes>,
    stats: &Stats,
    stop: &AtomicBool,
) {
    let mut batch = Vec::with_capacity(socket::BATCH);
    while !stop.load(Ordering::Relaxed) {
        if let Err(err) = receiver.recv_batch(&mut batch) {
            log::error!("recv failed: {err}");
            continue;
        }
        for packet in batch.drain(..) {
            match tx.try_send(packet) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => stats.dropped.inc(),
                Err(TrySendError::Disconnected(_)) => return,
            }
        }
    }
}
