//! Recording raw datagrams to a file and replaying them through a
//! [`Deshredder`]. Fixtures captured from a live port make tests and reviews
//! independent of having a shred feed at hand.
//!
//! File layout: an 8-byte magic, then records of
//! `u64 LE unix nanoseconds | u16 LE length | bytes`.

use {
    crate::{
        deshredder::{Deshredder, EntryBatch},
        pipeline::EntrySink,
    },
    std::{
        fs::File,
        io::{self, BufReader, BufWriter, Read, Write},
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    },
};

const MAGIC: &[u8; 8] = b"SHREDS\x00\x01";

pub struct Writer<W: Write> {
    inner: W,
}

impl Writer<BufWriter<File>> {
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::new(BufWriter::new(File::create(path)?))
    }
}

impl<W: Write> Writer<W> {
    pub fn new(mut inner: W) -> io::Result<Self> {
        inner.write_all(MAGIC)?;
        Ok(Self { inner })
    }

    /// Append a datagram stamped with the current time.
    pub fn write(&mut self, packet: &[u8]) -> io::Result<()> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        self.write_at(nanos, packet)
    }

    pub fn write_at(&mut self, unix_nanos: u64, packet: &[u8]) -> io::Result<()> {
        let len = u16::try_from(packet.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet longer than u16"))?;
        self.inner.write_all(&unix_nanos.to_le_bytes())?;
        self.inner.write_all(&len.to_le_bytes())?;
        self.inner.write_all(packet)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub struct Record {
    pub unix_nanos: u64,
    pub packet: Vec<u8>,
}

pub struct Reader<R: Read> {
    inner: R,
}

impl Reader<BufReader<File>> {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::new(BufReader::new(File::open(path)?))
    }
}

impl<R: Read> Reader<R> {
    pub fn new(mut inner: R) -> io::Result<Self> {
        let mut magic = [0u8; 8];
        inner.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a shred fixture",
            ));
        }
        Ok(Self { inner })
    }
}

impl<R: Read> Iterator for Reader<R> {
    type Item = io::Result<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut header = [0u8; 10];
        match self.inner.read_exact(&mut header) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return None,
            Err(err) => return Some(Err(err)),
        }
        let unix_nanos = u64::from_le_bytes(header[..8].try_into().unwrap());
        let len = u16::from_le_bytes([header[8], header[9]]);
        let mut packet = vec![0u8; usize::from(len)];
        Some(
            self.inner
                .read_exact(&mut packet)
                .map(|()| Record { unix_nanos, packet }),
        )
    }
}

/// Push every record of a fixture through `deshredder`, handing batches to
/// `sink`. Returns the number of packets replayed.
pub fn replay<R: Read>(
    reader: Reader<R>,
    deshredder: &mut Deshredder,
    sink: &mut impl EntrySink,
) -> io::Result<usize> {
    let mut out: Vec<EntryBatch> = Vec::new();
    let mut count = 0;
    for record in reader {
        deshredder.push(record?.packet, &mut out);
        for batch in out.drain(..) {
            sink.on_batch(batch);
        }
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf).unwrap();
            w.write_at(1, b"abc").unwrap();
            w.write_at(2, &[0u8; 1203]).unwrap();
        }
        let records: Vec<Record> = Reader::new(&buf[..]).unwrap().map(Result::unwrap).collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].unix_nanos, 1);
        assert_eq!(records[0].packet, b"abc");
        assert_eq!(records[1].packet.len(), 1203);
        assert!(Reader::new(&b"nope"[..]).is_err());
    }
}
