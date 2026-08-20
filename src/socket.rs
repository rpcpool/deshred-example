//! The UDP side: binding the port and pulling datagrams off it in batches.
//!
//! Shreds arrive in bursts of a few thousand packets per slot. Two things
//! matter on the receive path: the kernel buffer must be large enough to
//! absorb a burst while the consumer is busy, and the syscall count per
//! packet must stay low. On Linux `recvmmsg` drains up to [`BATCH`] datagrams
//! per call into one buffer; each datagram is then handed out as a `Bytes`
//! slice of that buffer, so a batch costs one allocation, not one per packet.
//! Elsewhere a plain `recv` per packet is used.

use {
    crate::shred::MAX_PACKET_SIZE,
    bytes::{Bytes, BytesMut},
    socket2::{Domain, Protocol, Socket, Type},
    std::{
        io,
        net::{SocketAddr, UdpSocket},
    },
};

/// Datagrams drained per `recvmmsg` call.
pub const BATCH: usize = 64;

/// Bind `addr` with a `recv_buffer_bytes` kernel receive buffer.
///
/// The kernel caps the request at `net.core.rmem_max`; when that happens a
/// warning says what to raise. The default buffer (often 200 KiB) overflows
/// the moment the consumer stalls for a few milliseconds.
pub fn bind(addr: SocketAddr, recv_buffer_bytes: usize) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_recv_buffer_size(recv_buffer_bytes)?;
    socket.bind(&addr.into())?;
    let effective = socket.recv_buffer_size()?;
    // Linux reports double the value it was asked for (it counts bookkeeping).
    if effective < recv_buffer_bytes {
        log::warn!(
            "receive buffer capped at {effective} bytes (asked for {recv_buffer_bytes}); \
             raise it with: sysctl -w net.core.rmem_max={recv_buffer_bytes}"
        );
    }
    Ok(socket.into())
}

/// Batched receiver over a bound socket.
pub struct Receiver {
    socket: UdpSocket,
    #[cfg(target_os = "linux")]
    headers: nix::sys::socket::MultiHeaders<()>,
}

impl Receiver {
    /// Set a read timeout on the socket first if [`Receiver::recv_batch`]
    /// must not block forever on a quiet port. The receiver is not `Send`
    /// (it keeps kernel-facing pointers), so build it on the receiving thread.
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket,
            #[cfg(target_os = "linux")]
            headers: nix::sys::socket::MultiHeaders::preallocate(BATCH, None),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Block for at least one datagram (or the timeout), then take whatever
    /// else is already queued, up to [`BATCH`]. Returns the number received;
    /// zero means the timeout elapsed.
    pub fn recv_batch(&mut self, out: &mut Vec<Bytes>) -> io::Result<usize> {
        let mut buf = BytesMut::zeroed(BATCH * MAX_PACKET_SIZE);
        let mut lens = [0usize; BATCH];
        let received = match self.recv_into(&mut buf, &mut lens) {
            Ok(n) => n,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                0
            }
            Err(err) => return Err(err),
        };
        for &len in &lens[..received] {
            let mut packet = buf.split_to(MAX_PACKET_SIZE);
            packet.truncate(len);
            out.push(packet.freeze());
        }
        Ok(received)
    }

    #[cfg(target_os = "linux")]
    fn recv_into(&mut self, buf: &mut [u8], lens: &mut [usize; BATCH]) -> io::Result<usize> {
        use {
            nix::sys::socket::{MsgFlags, recvmmsg},
            std::{io::IoSliceMut, os::fd::AsRawFd},
        };
        let mut chunks = buf.chunks_mut(MAX_PACKET_SIZE);
        let mut slices: [[IoSliceMut<'_>; 1]; BATCH] =
            std::array::from_fn(|_| [IoSliceMut::new(chunks.next().unwrap())]);
        // MSG_WAITFORONE: block for the first datagram (bounded by the socket
        // read timeout), return as soon as the queue is empty after that. The
        // recvmmsg timeout argument is not used because the kernel only
        // checks it after a datagram arrives.
        let results = recvmmsg(
            self.socket.as_raw_fd(),
            &mut self.headers,
            slices.iter_mut(),
            MsgFlags::MSG_WAITFORONE,
            None,
        )
        .map_err(io::Error::from)?;
        let mut n = 0;
        for msg in results {
            lens[n] = msg.bytes;
            n += 1;
        }
        Ok(n)
    }

    #[cfg(not(target_os = "linux"))]
    fn recv_into(&mut self, buf: &mut [u8], lens: &mut [usize; BATCH]) -> io::Result<usize> {
        lens[0] = self.socket.recv(&mut buf[..MAX_PACKET_SIZE])?;
        Ok(1)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, std::time::Duration};

    #[test]
    fn receives_batches_from_loopback() {
        let socket = bind("127.0.0.1:0".parse().unwrap(), 1 << 20).unwrap();
        let addr = socket.local_addr().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut receiver = Receiver::new(socket);
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        for i in 0..10u8 {
            sender.send_to(&vec![i; 1203], addr).unwrap();
        }
        let mut out = Vec::new();
        let mut total = 0;
        while total < 10 {
            let n = receiver.recv_batch(&mut out).unwrap();
            assert!(n > 0, "timed out");
            total += n;
        }
        assert_eq!(out.len(), 10);
        for (i, packet) in out.iter().enumerate() {
            assert_eq!(packet.len(), 1203);
            assert!(packet.iter().all(|&b| b == i as u8));
        }
        assert_eq!(receiver.recv_batch(&mut out).unwrap(), 0);
    }
}
