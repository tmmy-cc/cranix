//! Serialisation primitives shared by the worker protocol and NARs: every
//! value is a little-endian u64 or a length-prefixed byte string padded
//! with zeros to a multiple of 8 bytes.

use std::io::{self, Read, Write};

/// Upper bound for a single string read from the wire, guarding against
/// allocating whatever length a corrupt peer announces.
const MAX_STRING: u64 = 64 << 20;

pub fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

pub trait ReadExt: Read {
    fn read_u64(&mut self) -> io::Result<u64> {
        let mut b = [0u8; 8];
        self.read_exact(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn read_bool(&mut self) -> io::Result<bool> {
        Ok(self.read_u64()? != 0)
    }

    fn read_bytes(&mut self) -> io::Result<Vec<u8>> {
        let len = self.read_u64()?;
        if len > MAX_STRING {
            return Err(bad(format!("string of {len} bytes on the wire is too long")));
        }
        let mut v = vec![0u8; len as usize];
        self.read_exact(&mut v)?;
        let rem = (len % 8) as usize;
        if rem != 0 {
            let mut pad = [0u8; 8];
            self.read_exact(&mut pad[..8 - rem])?;
            if pad[..8 - rem].iter().any(|&b| b != 0) {
                return Err(bad("non-zero padding on the wire"));
            }
        }
        Ok(v)
    }

    fn read_string(&mut self) -> io::Result<String> {
        String::from_utf8(self.read_bytes()?).map_err(|_| bad("string on the wire is not UTF-8"))
    }

    fn read_strings(&mut self) -> io::Result<Vec<String>> {
        let n = self.read_u64()?;
        (0..n).map(|_| self.read_string()).collect()
    }
}

impl<R: Read + ?Sized> ReadExt for R {}

pub trait WriteExt: Write {
    fn write_u64(&mut self, n: u64) -> io::Result<()> {
        self.write_all(&n.to_le_bytes())
    }

    fn write_bool(&mut self, b: bool) -> io::Result<()> {
        self.write_u64(b as u64)
    }

    fn write_bytes(&mut self, b: &[u8]) -> io::Result<()> {
        self.write_u64(b.len() as u64)?;
        self.write_all(b)?;
        let rem = b.len() % 8;
        if rem != 0 {
            self.write_all(&[0u8; 8][..8 - rem])?;
        }
        Ok(())
    }

    fn write_str(&mut self, s: &str) -> io::Result<()> {
        self.write_bytes(s.as_bytes())
    }

    fn write_strings<'a>(&mut self, items: impl IntoIterator<Item = &'a str>) -> io::Result<()> {
        let items: Vec<&str> = items.into_iter().collect();
        self.write_u64(items.len() as u64)?;
        for s in items {
            self.write_str(s)?;
        }
        Ok(())
    }
}

impl<W: Write + ?Sized> WriteExt for W {}

/// Reads a framed stream: chunks of `u64 length` + unpadded data, ended by
/// an empty chunk. Dropping it consumes any frames left, so the connection
/// stays in sync after the reader gives up early.
pub struct FramedReader<'a, R: Read + ?Sized> {
    inner: &'a mut R,
    left: u64,
    eof: bool,
}

impl<'a, R: Read + ?Sized> FramedReader<'a, R> {
    pub fn new(inner: &'a mut R) -> Self {
        FramedReader { inner, left: 0, eof: false }
    }

    pub fn drain(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 1 << 14];
        while self.read(&mut buf)? != 0 {}
        Ok(())
    }
}

impl<R: Read + ?Sized> Read for FramedReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.eof || buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            self.left = self.inner.read_u64()?;
            if self.left == 0 {
                self.eof = true;
                return Ok(0);
            }
        }
        let n = (buf.len() as u64).min(self.left) as usize;
        let got = self.inner.read(&mut buf[..n])?;
        if got == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "framed stream ended early"));
        }
        self.left -= got as u64;
        Ok(got)
    }
}

impl<R: Read + ?Sized> Drop for FramedReader<'_, R> {
    fn drop(&mut self) {
        let _ = self.drain();
    }
}

/// Writes a framed stream; `finish` sends the terminating empty frame.
pub struct FramedWriter<'a, W: Write + ?Sized> {
    inner: &'a mut W,
    buf: Vec<u8>,
}

const FRAME: usize = 32 << 10;

impl<'a, W: Write + ?Sized> FramedWriter<'a, W> {
    pub fn new(inner: &'a mut W) -> Self {
        FramedWriter { inner, buf: Vec::with_capacity(FRAME) }
    }

    fn flush_frame(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            self.inner.write_u64(self.buf.len() as u64)?;
            self.inner.write_all(&self.buf)?;
            self.buf.clear();
        }
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<()> {
        self.flush_frame()?;
        self.inner.write_u64(0)?;
        self.inner.flush()
    }
}

impl<W: Write + ?Sized> Write for FramedWriter<'_, W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min(FRAME - self.buf.len());
        self.buf.extend_from_slice(&data[..n]);
        if self.buf.len() == FRAME {
            self.flush_frame()?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_frame()?;
        self.inner.flush()
    }
}

/// Copies exactly one NAR from `r` to `w`, parsing its structure to find
/// where it ends. Used where a NAR is embedded in a stream without a length.
pub fn copy_nar(r: &mut (impl Read + ?Sized), w: &mut (impl Write + ?Sized)) -> io::Result<()> {
    struct Tee<'a, R: ?Sized, W: ?Sized> {
        r: &'a mut R,
        w: &'a mut W,
    }
    impl<R: Read + ?Sized, W: Write + ?Sized> Tee<'_, R, W> {
        fn u64(&mut self) -> io::Result<u64> {
            let n = self.r.read_u64()?;
            self.w.write_u64(n)?;
            Ok(n)
        }
        fn raw(&mut self, len: u64) -> io::Result<()> {
            let padded = len.div_ceil(8) * 8;
            let copied = io::copy(&mut (&mut *self.r).take(padded), self.w)?;
            if copied != padded {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated NAR"));
            }
            Ok(())
        }
        fn s(&mut self) -> io::Result<Vec<u8>> {
            let b = self.r.read_bytes()?;
            self.w.write_bytes(&b)?;
            Ok(b)
        }
        fn expect(&mut self, want: &str) -> io::Result<()> {
            let got = self.s()?;
            if got != want.as_bytes() {
                return Err(bad(format!("expected '{want}' in NAR, got '{}'", String::from_utf8_lossy(&got))));
            }
            Ok(())
        }
        fn node(&mut self) -> io::Result<()> {
            self.expect("(")?;
            self.expect("type")?;
            match &self.s()?[..] {
                b"regular" => loop {
                    match &self.s()?[..] {
                        b"executable" => self.expect("")?,
                        b"contents" => {
                            let len = self.u64()?;
                            self.raw(len)?;
                        }
                        b")" => return Ok(()),
                        t => return Err(bad(format!("unexpected '{}' in NAR file", String::from_utf8_lossy(t)))),
                    }
                },
                b"symlink" => {
                    self.expect("target")?;
                    self.s()?;
                    self.expect(")")
                }
                b"directory" => loop {
                    match &self.s()?[..] {
                        b")" => return Ok(()),
                        b"entry" => {
                            self.expect("(")?;
                            self.expect("name")?;
                            self.s()?;
                            self.expect("node")?;
                            self.node()?;
                            self.expect(")")?;
                        }
                        t => return Err(bad(format!("unexpected '{}' in NAR directory", String::from_utf8_lossy(t)))),
                    }
                },
                t => Err(bad(format!("unknown NAR node type '{}'", String::from_utf8_lossy(t)))),
            }
        }
    }
    let mut t = Tee { r, w };
    t.expect("nix-archive-1")?;
    t.node()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_padded() {
        let mut v = Vec::new();
        v.write_str("abc").unwrap();
        assert_eq!(v, [3, 0, 0, 0, 0, 0, 0, 0, b'a', b'b', b'c', 0, 0, 0, 0, 0]);
        let mut r = &v[..];
        assert_eq!(r.read_string().unwrap(), "abc");
        assert!(r.is_empty());
    }

    #[test]
    fn framed_roundtrip_and_drain() {
        let data: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
        let mut v = Vec::new();
        let mut w = FramedWriter::new(&mut v);
        w.write_all(&data).unwrap();
        w.finish().unwrap();
        v.write_u64(42).unwrap();

        let mut r = &v[..];
        let mut got = Vec::new();
        FramedReader::new(&mut r).read_to_end(&mut got).unwrap();
        assert_eq!(got, data);
        assert_eq!(r.read_u64().unwrap(), 42);

        // A reader dropped half-way still leaves the stream after the frames.
        let mut r = &v[..];
        let mut f = FramedReader::new(&mut r);
        let mut small = [0u8; 10];
        f.read_exact(&mut small).unwrap();
        drop(f);
        assert_eq!(r.read_u64().unwrap(), 42);
    }

    #[test]
    fn copy_nar_stops_at_end() {
        let mut nar = Vec::new();
        cranix_core::nar::dump_bytes(b"hello world", true, &mut nar).unwrap();
        let mut stream = nar.clone();
        stream.extend_from_slice(b"trailing");
        let mut r = &stream[..];
        let mut out = Vec::new();
        copy_nar(&mut r, &mut out).unwrap();
        assert_eq!(out, nar);
        assert_eq!(r, b"trailing");
    }
}
