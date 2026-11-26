//! Unpacking tarballs like Nix's `unpackTarfileToSink`: entries keep only
//! their type, contents and owner-executable bit, hard links become
//! copies, and the newest entry mtime is reported as `lastModified`.
//!
//! The archive is decompressed by the matching command line tool and the
//! tar stream (ustar, pax and GNU long names) is parsed here. Zip files
//! are extracted with `bsdtar`/`unzip`.

use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::Result;

fn decompressor(magic: &[u8]) -> Option<&'static [&'static str]> {
    if magic.starts_with(&[0x1f, 0x8b]) {
        Some(&["gzip", "-dc"])
    } else if magic.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        Some(&["xz", "-dc"])
    } else if magic.starts_with(b"BZh") {
        Some(&["bzip2", "-dc"])
    } else if magic.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some(&["zstd", "-dc"])
    } else {
        None
    }
}

/// Unpacks `archive` into the (empty) directory `dest`. Returns the
/// newest mtime among the entries.
pub fn unpack(archive: &Path, dest: &Path) -> Result<u64> {
    let mut magic = [0u8; 6];
    let n = fs::File::open(archive).and_then(|mut f| f.read(&mut magic)).map_err(|e| format!("reading '{}': {e}", archive.display()))?;
    let magic = &magic[..n];
    if magic.starts_with(b"PK") {
        return unpack_zip(archive, dest);
    }
    let r = match decompressor(magic) {
        Some(cmd) => {
            let mut child = Command::new(cmd[0])
                .args(&cmd[1..])
                .arg(archive)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| format!("running {}: {e}", cmd[0]))?;
            let stdout = child.stdout.take().unwrap();
            let r = unpack_stream(io::BufReader::with_capacity(1 << 20, stdout), dest);
            let out = child.wait_with_output().map_err(|e| e.to_string())?;
            if r.is_ok() && !out.status.success() {
                return Err(format!("decompressing '{}': {}", archive.display(), String::from_utf8_lossy(&out.stderr).trim()));
            }
            r
        }
        None => {
            let f = fs::File::open(archive).map_err(|e| e.to_string())?;
            unpack_stream(io::BufReader::with_capacity(1 << 20, f), dest)
        }
    };
    r.map_err(|e| format!("unpacking '{}': {e}", archive.display()))
}

fn unpack_zip(archive: &Path, dest: &Path) -> Result<u64> {
    let bsdtar = ["/usr/bin/bsdtar", "/usr/bin/tar", "bsdtar"].into_iter().find(|t| !t.starts_with('/') || Path::new(t).exists());
    let st = match bsdtar {
        Some(t) => Command::new(t).arg("-xf").arg(archive).arg("-C").arg(dest).status(),
        None => Command::new("unzip").arg("-q").arg(archive).arg("-d").arg(dest).status(),
    }
    .map_err(|e| format!("extracting '{}': {e}", archive.display()))?;
    if !st.success() {
        return Err(format!("extracting '{}' failed", archive.display()));
    }
    normalise_modes(dest);
    Ok(crate::storeutil::max_mtime(dest))
}

fn normalise_modes(p: &Path) {
    if let Ok(md) = fs::symlink_metadata(p) {
        if md.is_dir() {
            let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
            for e in fs::read_dir(p).into_iter().flatten().flatten() {
                normalise_modes(&e.path());
            }
        } else if md.is_file() {
            let exec = md.permissions().mode() & 0o100 != 0;
            let _ = fs::set_permissions(p, fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 }));
        }
    }
}

fn octal(field: &[u8]) -> io::Result<u64> {
    // Base-256 (GNU) for large values: high bit of the first byte set.
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v: u64 = (field[0] & 0x7f) as u64;
        for &b in &field[1..] {
            v = (v << 8) | b as u64;
        }
        return Ok(v);
    }
    let s: String = field.iter().take_while(|&&b| b != 0).map(|&b| b as char).collect();
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|_| io::Error::other(format!("invalid number '{s}' in tar header")))
}

fn cstr(field: &[u8]) -> Vec<u8> {
    field.iter().take_while(|&&b| b != 0).copied().collect()
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut got = 0;
    while got < buf.len() {
        let n = r.read(&mut buf[got..])?;
        if n == 0 {
            if got == 0 {
                return Ok(false);
            }
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated tar archive"));
        }
        got += n;
    }
    Ok(true)
}

fn read_data<R: Read>(r: &mut R, size: u64) -> io::Result<Vec<u8>> {
    let mut v = vec![0u8; size as usize];
    r.read_exact(&mut v)?;
    skip_padding(r, size)?;
    Ok(v)
}

fn skip_padding<R: Read>(r: &mut R, size: u64) -> io::Result<()> {
    let pad = (512 - size % 512) % 512;
    io::copy(&mut r.take(pad), &mut io::sink())?;
    Ok(())
}

/// Turns an archive member name into components below the root,
/// dropping `.` and empty components.
fn components(name: &[u8]) -> io::Result<Vec<String>> {
    let s = String::from_utf8_lossy(name);
    let mut out: Vec<String> = Vec::new();
    for c in s.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                if out.pop().is_none() {
                    return Err(io::Error::other(format!("tar member '{s}' points outside the archive")));
                }
            }
            c => out.push(c.to_string()),
        }
    }
    Ok(out)
}

fn target(dest: &Path, comps: &[String]) -> PathBuf {
    let mut p = dest.to_path_buf();
    for c in comps {
        p.push(c);
    }
    p
}

fn prepare_parent(p: &Path) -> io::Result<()> {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    // A later member replaces an earlier one of the same name.
    if let Ok(md) = fs::symlink_metadata(p) {
        if md.is_dir() {
            fs::remove_dir_all(p)?;
        } else {
            fs::remove_file(p)?;
        }
    }
    Ok(())
}

fn parse_pax(data: &[u8], out: &mut Vec<(String, Vec<u8>)>) {
    let mut rest = data;
    while !rest.is_empty() {
        let Some(sp) = rest.iter().position(|&b| b == b' ') else { break };
        let Ok(len) = std::str::from_utf8(&rest[..sp]).unwrap_or("").parse::<usize>() else { break };
        if len == 0 || len > rest.len() {
            break;
        }
        let rec = &rest[sp + 1..len];
        let rec = rec.strip_suffix(b"\n").unwrap_or(rec);
        if let Some(eq) = rec.iter().position(|&b| b == b'=') {
            out.push((String::from_utf8_lossy(&rec[..eq]).into_owned(), rec[eq + 1..].to_vec()));
        }
        rest = &rest[len..];
    }
}

pub fn unpack_stream<R: Read>(mut r: R, dest: &Path) -> io::Result<u64> {
    let mut last_modified = 0u64;
    let mut hdr = [0u8; 512];
    let mut long_name: Option<Vec<u8>> = None;
    let mut long_link: Option<Vec<u8>> = None;
    let mut pax: Vec<(String, Vec<u8>)> = Vec::new();
    loop {
        if !read_exact_or_eof(&mut r, &mut hdr)? {
            break;
        }
        if hdr.iter().all(|&b| b == 0) {
            // End-of-archive marker (two zero blocks); trailing data is ignored.
            break;
        }
        let mut size = octal(&hdr[124..136])?;
        let mut mtime = octal(&hdr[136..148])?;
        let mode = octal(&hdr[100..108])?;
        let ty = hdr[156];
        let mut name = cstr(&hdr[0..100]);
        if &hdr[257..263] == b"ustar\0" && hdr[345] != 0 {
            let mut p = cstr(&hdr[345..500]);
            p.push(b'/');
            p.extend(name);
            name = p;
        }
        let mut link = cstr(&hdr[157..257]);
        match ty {
            b'x' => {
                let data = read_data(&mut r, size)?;
                parse_pax(&data, &mut pax);
                continue;
            }
            b'g' => {
                read_data(&mut r, size)?;
                continue;
            }
            b'L' => {
                long_name = Some(cstr(&read_data(&mut r, size)?));
                continue;
            }
            b'K' => {
                long_link = Some(cstr(&read_data(&mut r, size)?));
                continue;
            }
            _ => {}
        }
        if let Some(n) = long_name.take() {
            name = n;
        }
        if let Some(l) = long_link.take() {
            link = l;
        }
        for (k, v) in pax.drain(..) {
            match k.as_str() {
                "path" => name = v,
                "linkpath" => link = v,
                "size" => size = String::from_utf8_lossy(&v).parse().unwrap_or(size),
                "mtime" => {
                    let s = String::from_utf8_lossy(&v);
                    let whole = s.split('.').next().unwrap_or("0");
                    mtime = whole.parse::<i64>().unwrap_or(0).max(0) as u64;
                }
                _ => {}
            }
        }
        last_modified = last_modified.max(mtime);
        let comps = components(&name)?;
        let path = target(dest, &comps);
        match ty {
            b'5' => {
                if !comps.is_empty() {
                    if fs::symlink_metadata(&path).map(|m| !m.is_dir()).unwrap_or(false) {
                        fs::remove_file(&path)?;
                    }
                    fs::create_dir_all(&path)?;
                }
                io::copy(&mut (&mut r).take(size), &mut io::sink())?;
                skip_padding(&mut r, size)?;
            }
            b'0' | 0 | b'7' => {
                if comps.is_empty() {
                    return Err(io::Error::other("tar member without a name"));
                }
                prepare_parent(&path)?;
                let mut f = fs::File::create(&path)?;
                let copied = io::copy(&mut (&mut r).take(size), &mut f)?;
                if copied != size {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated tar archive"));
                }
                skip_padding(&mut r, size)?;
                let exec = mode & 0o100 != 0;
                fs::set_permissions(&path, fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 }))?;
            }
            b'2' => {
                prepare_parent(&path)?;
                std::os::unix::fs::symlink(String::from_utf8_lossy(&link).as_ref(), &path)?;
                skip_data(&mut r, size)?;
            }
            b'1' => {
                let src = target(dest, &components(&link)?);
                prepare_parent(&path)?;
                fs::copy(&src, &path).map_err(|e| io::Error::other(format!("hard link to '{}': {e}", String::from_utf8_lossy(&link))))?;
                skip_data(&mut r, size)?;
            }
            t => {
                return Err(io::Error::other(format!(
                    "file '{}' in tarball has unsupported file type {}",
                    String::from_utf8_lossy(&name),
                    t as char
                )))
            }
        }
    }
    Ok(last_modified)
}

fn skip_data<R: Read>(r: &mut R, size: u64) -> io::Result<()> {
    io::copy(&mut r.take(size), &mut io::sink())?;
    skip_padding(r, size)
}

/// The directory a tarball's contents are rooted at: its only member if
/// that is a directory, otherwise the unpack directory itself.
pub fn singleton_root(dest: &Path) -> PathBuf {
    let entries: Vec<_> = fs::read_dir(dest).into_iter().flatten().flatten().collect();
    if entries.len() == 1 {
        let p = entries[0].path();
        if fs::symlink_metadata(&p).map(|m| m.is_dir()).unwrap_or(false) {
            return p;
        }
    }
    dest.to_path_buf()
}
