//! The Nix ARchive format: a canonical, streaming serialisation of a file
//! system object (regular file, executable bit, symlink or directory).
//!
//! Every token is a little-endian u64 length followed by the bytes, padded
//! with zeros to a multiple of 8.

use std::fs;
use std::io::{self, BufWriter, Read, Write};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

const MAGIC: &str = "nix-archive-1";

/// Decides whether an entry is included; receives the path and whether it is
/// a directory.
pub type Filter<'a> = &'a mut dyn FnMut(&Path, &fs::Metadata) -> io::Result<bool>;

struct Writer<W: Write> {
    out: W,
}

impl<W: Write> Writer<W> {
    fn bytes(&mut self, b: &[u8]) -> io::Result<()> {
        self.out.write_all(&(b.len() as u64).to_le_bytes())?;
        self.out.write_all(b)?;
        self.pad(b.len() as u64)
    }

    fn pad(&mut self, len: u64) -> io::Result<()> {
        let rem = (len % 8) as usize;
        if rem != 0 {
            self.out.write_all(&[0u8; 8][..8 - rem])?;
        }
        Ok(())
    }

    fn s(&mut self, s: &str) -> io::Result<()> {
        self.bytes(s.as_bytes())
    }

    fn node(&mut self, path: &Path, filter: &mut Option<Filter<'_>>) -> io::Result<()> {
        let md = fs::symlink_metadata(path)?;
        self.s("(")?;
        let ft = md.file_type();
        if ft.is_symlink() {
            self.s("type")?;
            self.s("symlink")?;
            self.s("target")?;
            let t = fs::read_link(path)?;
            self.bytes(t.as_os_str().as_encoded_bytes())?;
        } else if ft.is_file() {
            self.s("type")?;
            self.s("regular")?;
            if md.permissions().mode() & 0o100 != 0 {
                self.s("executable")?;
                self.s("")?;
            }
            self.s("contents")?;
            let len = md.len();
            self.out.write_all(&len.to_le_bytes())?;
            let mut f = fs::File::open(path)?;
            let copied = io::copy(&mut (&mut f).take(len), &mut self.out)?;
            if copied != len {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("file '{}' changed while archiving", path.display())));
            }
            self.pad(len)?;
        } else if ft.is_dir() {
            self.s("type")?;
            self.s("directory")?;
            let mut entries: Vec<_> = fs::read_dir(path)?.collect::<io::Result<_>>()?;
            entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
            for e in entries {
                let child = e.path();
                if let Some(f) = filter.as_mut() {
                    if !f(&child, &fs::symlink_metadata(&child)?)? {
                        continue;
                    }
                }
                self.s("entry")?;
                self.s("(")?;
                self.s("name")?;
                self.bytes(e.file_name().as_encoded_bytes())?;
                self.s("node")?;
                self.node(&child, filter)?;
                self.s(")")?;
            }
        } else {
            return Err(io::Error::new(io::ErrorKind::Unsupported, format!("file '{}' has an unsupported type", path.display())));
        }
        self.s(")")
    }
}

/// Serialises `path` as a NAR into `out`.
pub fn dump(path: &Path, out: impl Write) -> io::Result<()> {
    dump_filtered(path, out, None)
}

pub fn dump_filtered(path: &Path, out: impl Write, mut filter: Option<Filter<'_>>) -> io::Result<()> {
    let mut w = Writer { out: BufWriter::with_capacity(1 << 16, out) };
    w.s(MAGIC)?;
    w.node(path, &mut filter)?;
    w.out.flush()
}

/// NAR of a single regular file held in memory.
pub fn dump_bytes(contents: &[u8], executable: bool, out: impl Write) -> io::Result<()> {
    let mut w = Writer { out };
    w.s(MAGIC)?;
    w.s("(")?;
    w.s("type")?;
    w.s("regular")?;
    if executable {
        w.s("executable")?;
        w.s("")?;
    }
    w.s("contents")?;
    w.bytes(contents)?;
    w.s(")")
}

struct Reader<R: Read> {
    inp: R,
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

impl<R: Read> Reader<R> {
    fn u64(&mut self) -> io::Result<u64> {
        let mut b = [0u8; 8];
        self.inp.read_exact(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn skip_pad(&mut self, len: u64) -> io::Result<()> {
        let rem = (len % 8) as usize;
        if rem != 0 {
            let mut b = [0u8; 8];
            self.inp.read_exact(&mut b[..8 - rem])?;
            if b[..8 - rem].iter().any(|&x| x != 0) {
                return Err(bad("non-zero padding in NAR"));
            }
        }
        Ok(())
    }

    fn bytes(&mut self, max: u64) -> io::Result<Vec<u8>> {
        let len = self.u64()?;
        if len > max {
            return Err(bad("NAR string too long"));
        }
        let mut v = vec![0u8; len as usize];
        self.inp.read_exact(&mut v)?;
        self.skip_pad(len)?;
        Ok(v)
    }

    fn expect(&mut self, s: &str) -> io::Result<()> {
        let got = self.bytes(1024)?;
        if got != s.as_bytes() {
            return Err(bad(format!("expected '{s}' in NAR, got '{}'", String::from_utf8_lossy(&got))));
        }
        Ok(())
    }

    fn tag(&mut self) -> io::Result<String> {
        String::from_utf8(self.bytes(1024)?).map_err(|_| bad("invalid tag in NAR"))
    }

    fn node(&mut self, dest: &Path) -> io::Result<()> {
        self.expect("(")?;
        self.expect("type")?;
        match self.tag()?.as_str() {
            "regular" => {
                let mut t = self.tag()?;
                let mut exec = false;
                if t == "executable" {
                    self.expect("")?;
                    exec = true;
                    t = self.tag()?;
                }
                if t != "contents" {
                    return Err(bad("expected 'contents' in NAR"));
                }
                let len = self.u64()?;
                let mut f = fs::File::create(dest)?;
                let copied = io::copy(&mut (&mut self.inp).take(len), &mut f)?;
                if copied != len {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated NAR"));
                }
                self.skip_pad(len)?;
                if exec {
                    fs::set_permissions(dest, fs::Permissions::from_mode(0o755))?;
                }
                self.expect(")")
            }
            "symlink" => {
                self.expect("target")?;
                let t = self.bytes(4096)?;
                symlink(OsStr::from_bytes(&t), dest)?;
                self.expect(")")
            }
            "directory" => {
                fs::create_dir(dest)?;
                let mut prev: Option<Vec<u8>> = None;
                loop {
                    match self.tag()?.as_str() {
                        ")" => return Ok(()),
                        "entry" => {
                            self.expect("(")?;
                            self.expect("name")?;
                            let name = self.bytes(255)?;
                            if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') || name.contains(&0) {
                                return Err(bad("invalid file name in NAR"));
                            }
                            if prev.as_ref().is_some_and(|p| *p >= name) {
                                return Err(bad("NAR directory entries are not sorted"));
                            }
                            self.expect("node")?;
                            self.node(&dest.join(OsStr::from_bytes(&name)))?;
                            self.expect(")")?;
                            prev = Some(name);
                        }
                        t => return Err(bad(format!("unexpected '{t}' in NAR directory"))),
                    }
                }
            }
            t => Err(bad(format!("unknown NAR node type '{t}'"))),
        }
    }
}

/// Unpacks a NAR read from `inp` to `dest`, which must not exist.
pub fn restore(inp: impl Read, dest: &Path) -> io::Result<()> {
    let mut r = Reader { inp: io::BufReader::with_capacity(1 << 16, inp) };
    r.expect(MAGIC)?;
    r.node(dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{HashAlgo, HashSink};

    #[test]
    fn roundtrip_and_hash() {
        let tmp = std::env::temp_dir().join(format!("cranix-nar-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("src/sub")).unwrap();
        fs::write(tmp.join("src/a"), "hello\n").unwrap();
        fs::write(tmp.join("src/sub/x.sh"), "#!/bin/sh\n").unwrap();
        fs::set_permissions(tmp.join("src/sub/x.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("a", tmp.join("src/link")).unwrap();

        let mut nar = Vec::new();
        dump(&tmp.join("src"), &mut nar).unwrap();
        restore(&nar[..], &tmp.join("dst")).unwrap();
        let mut nar2 = Vec::new();
        dump(&tmp.join("dst"), &mut nar2).unwrap();
        assert_eq!(nar, nar2);

        let mut sink = HashSink::new(HashAlgo::Sha256);
        dump_bytes(b"hello\n", false, &mut sink).unwrap();
        let mut sink2 = HashSink::new(HashAlgo::Sha256);
        dump(&tmp.join("src/a"), &mut sink2).unwrap();
        assert_eq!(sink.finish(), sink2.finish());
        fs::remove_dir_all(&tmp).unwrap();
    }
}
