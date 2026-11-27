//! What binaries say about the code linked into them: the module list Go
//! writes into `.go.buildinfo`, and the crate list `cargo auditable`
//! writes into the `.dep-v0` section. Executables that carry no such list
//! and contain statically linked code are reported as unlisted.

use std::io::Read;
use std::path::Path;

/// A module or crate linked into a binary.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Embedded {
    /// `golang` or `cargo`.
    pub ecosystem: &'static str,
    pub name: String,
    pub version: String,
    /// The `h1:…` checksum of a Go module, or the SHA-256 of a crate.
    pub checksum: Option<String>,
    /// Where it was found: `derivation`, `source` or `binary`.
    pub found_in: &'static str,
}

impl Embedded {
    pub fn purl(&self) -> String {
        format!("pkg:{}/{}@{}", self.ecosystem, crate::purl_escape_path(&self.name), crate::purl_escape(&self.version))
    }
}

/// What one binary file says.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BinaryInfo {
    /// The main module of a Go binary.
    pub go_main: Option<String>,
    pub embedded: Vec<Embedded>,
    /// An executable with statically linked code and no list of it.
    pub unlisted: bool,
}

const GO_INFO_START: &[u8] = b"\x30\x77\xaf\x0c\x92\x74\x08\x02\x41\xe1\xc1\x07\xe6\xd6\x18\xe6";
const GO_INFO_END: &[u8] = b"\xf9\x32\x43\x31\x86\x18\x20\x72\x00\x82\x42\x10\x41\x16\xd8\xf2";
const GO_BUILDINFO_MAGIC: &[u8] = b"\xff Go buildinf:";

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The modules in Go's module information: `path`, `mod` and `dep` lines
/// between two sentinels. `=>` lines replace the module before them.
pub fn go_modules(data: &[u8]) -> Option<(Option<String>, Vec<Embedded>)> {
    let start = find(data, GO_INFO_START)? + GO_INFO_START.len();
    let len = find(&data[start..], GO_INFO_END)?;
    let text = String::from_utf8_lossy(&data[start..start + len]);
    let mut main = None;
    let mut mods: Vec<Embedded> = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["path", p, ..] => main = main.or(Some(p.to_string())),
            ["mod", p, v, rest @ ..] | ["dep", p, v, rest @ ..] => mods.push(Embedded {
                ecosystem: "golang",
                name: p.to_string(),
                version: v.to_string(),
                checksum: rest.first().map(|s| s.to_string()),
                found_in: "binary",
            }),
            ["=>", p, v, rest @ ..] => {
                if let Some(last) = mods.last_mut() {
                    last.name = p.to_string();
                    last.version = v.to_string();
                    last.checksum = rest.first().map(|s| s.to_string());
                }
            }
            _ => {}
        }
    }
    // The main module of a local build has version `(devel)`.
    mods.retain(|m| m.version != "(devel)");
    Some((main, mods))
}

/// A section of an ELF or 64-bit Mach-O file, by name.
pub fn section<'a>(data: &'a [u8], name: &str) -> Option<&'a [u8]> {
    if data.starts_with(b"\x7fELF") {
        return elf_section(data, name);
    }
    if data.len() >= 4 && matches!(u32::from_le_bytes(data[..4].try_into().ok()?), 0xfeedfacf) {
        return macho_section(data, name);
    }
    None
}

struct Rd<'a> {
    d: &'a [u8],
    le: bool,
}

impl Rd<'_> {
    fn u16(&self, o: usize) -> Option<u64> {
        let b: [u8; 2] = self.d.get(o..o + 2)?.try_into().ok()?;
        Some(if self.le { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) } as u64)
    }
    fn u32(&self, o: usize) -> Option<u64> {
        let b: [u8; 4] = self.d.get(o..o + 4)?.try_into().ok()?;
        Some(if self.le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) } as u64)
    }
    fn u64(&self, o: usize) -> Option<u64> {
        let b: [u8; 8] = self.d.get(o..o + 8)?.try_into().ok()?;
        Some(if self.le { u64::from_le_bytes(b) } else { u64::from_be_bytes(b) })
    }
    fn word(&self, o: usize, wide: bool) -> Option<u64> {
        if wide { self.u64(o) } else { self.u32(o) }
    }
}

/// Section headers of an ELF file: (name, offset, size, type).
fn elf_sections(data: &[u8]) -> Option<Vec<(String, usize, usize, u64)>> {
    let wide = *data.get(4)? == 2;
    let r = Rd { d: data, le: *data.get(5)? == 1 };
    let (shoff, shentsize, shnum, shstrndx) = if wide {
        (r.u64(0x28)?, r.u16(0x3a)?, r.u16(0x3c)?, r.u16(0x3e)?)
    } else {
        (r.u32(0x20)?, r.u16(0x2e)?, r.u16(0x30)?, r.u16(0x32)?)
    };
    let hdr = |i: u64| (shoff + i * shentsize) as usize;
    let (off_at, size_at) = if wide { (0x18, 0x20) } else { (0x10, 0x14) };
    let strtab = r.word(hdr(shstrndx) + off_at, wide)? as usize;
    let mut out = Vec::new();
    for i in 0..shnum {
        let h = hdr(i);
        let name_off = r.u32(h)? as usize;
        let ty = r.u32(h + 4)?;
        let off = r.word(h + off_at, wide)? as usize;
        let size = r.word(h + size_at, wide)? as usize;
        let name_bytes = data.get(strtab + name_off..)?;
        let end = name_bytes.iter().position(|&b| b == 0)?;
        out.push((String::from_utf8_lossy(&name_bytes[..end]).into_owned(), off, size, ty));
    }
    Some(out)
}

fn elf_section<'a>(data: &'a [u8], name: &str) -> Option<&'a [u8]> {
    // SHT_NOBITS sections have no contents in the file.
    let (_, off, size, _) = elf_sections(data)?.into_iter().find(|(n, _, _, ty)| n == name && *ty != 8)?;
    data.get(off..off + size)
}

/// Whether an ELF file is an executable or shared object without a
/// program interpreter, that is statically linked.
fn elf_is_static_executable(data: &[u8]) -> bool {
    (|| {
        let wide = *data.get(4)? == 2;
        let r = Rd { d: data, le: *data.get(5)? == 1 };
        let ty = r.u16(0x10)?;
        let (phoff, phentsize, phnum) = if wide { (r.u64(0x20)?, r.u16(0x36)?, r.u16(0x38)?) } else { (r.u32(0x1c)?, r.u16(0x2a)?, r.u16(0x2c)?) };
        let mut interp = false;
        let mut dynamic = false;
        for i in 0..phnum {
            match r.u32((phoff + i * phentsize) as usize)? {
                3 => interp = true,
                2 => dynamic = true,
                _ => {}
            }
        }
        // ET_EXEC, or ET_DYN without PT_DYNAMIC (static-pie has both a
        // dynamic segment and no interpreter; shared libraries have no
        // interpreter but are dynamic).
        Some((ty == 2 && !interp) || (ty == 3 && !interp && !dynamic))
    })()
    .unwrap_or(false)
}

fn macho_section<'a>(data: &'a [u8], name: &str) -> Option<&'a [u8]> {
    let r = Rd { d: data, le: true };
    let ncmds = r.u32(16)?;
    let mut at = 32usize;
    for _ in 0..ncmds {
        let cmd = r.u32(at)?;
        let size = r.u32(at + 4)? as usize;
        // LC_SEGMENT_64
        if cmd == 0x19 {
            let nsects = r.u32(at + 64)?;
            for s in 0..nsects as usize {
                let sh = at + 72 + s * 80;
                let raw = data.get(sh..sh + 16)?;
                let end = raw.iter().position(|&b| b == 0).unwrap_or(16);
                if &raw[..end] == name.as_bytes() {
                    let size = r.u64(sh + 40)? as usize;
                    let off = r.u32(sh + 48)? as usize;
                    return data.get(off..off + size);
                }
            }
        }
        at += size;
    }
    None
}

/// The crates `cargo auditable` recorded: zlib-compressed JSON with a
/// `packages` list.
pub fn auditable_crates(data: &[u8]) -> Option<Vec<Embedded>> {
    let sec = section(data, ".dep-v0")?;
    let mut json = Vec::new();
    flate2::read::ZlibDecoder::new(sec).take(64 << 20).read_to_end(&mut json).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&json).ok()?;
    let mut out = Vec::new();
    for p in v["packages"].as_array()? {
        // The root crate is the package itself.
        if p["root"].as_bool() == Some(true) {
            continue;
        }
        let (Some(name), Some(version)) = (p["name"].as_str(), p["version"].as_str()) else { continue };
        // Build-time dependencies are not in the binary.
        if p["kind"].as_str() == Some("build") {
            continue;
        }
        out.push(Embedded { ecosystem: "cargo", name: name.into(), version: version.into(), checksum: None, found_in: "binary" });
    }
    Some(out)
}

fn is_rust(data: &[u8]) -> bool {
    section(data, ".rustc").is_some() || find(data, b"rust_begin_unwind").is_some() || find(data, b"/rustc/").is_some()
}

/// Reads the binary at `path`; `None` for files that are not ELF or Mach-O.
pub fn inspect(path: &Path) -> Option<BinaryInfo> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).ok()?;
    let object = &magic == b"\x7fELF" || u32::from_le_bytes(magic) == 0xfeedfacf;
    if !object {
        return None;
    }
    let data = std::fs::read(path).ok()?;
    let mut info = BinaryInfo::default();
    let go = find(&data, GO_BUILDINFO_MAGIC).is_some();
    if let Some((main, mods)) = go_modules(&data) {
        info.go_main = main;
        info.embedded = mods;
        return Some(info);
    }
    if let Some(crates) = auditable_crates(&data) {
        info.embedded = crates;
        return Some(info);
    }
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).map(|m| m.permissions().mode() & 0o111 != 0).unwrap_or(false)
    };
    info.unlisted = executable && (go || is_rust(&data) || (data.starts_with(b"\x7fELF") && elf_is_static_executable(&data)));
    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_module_lines() {
        let mut data = b"junk".to_vec();
        data.extend(GO_INFO_START);
        data.extend(b"path\texample.com/app\nmod\texample.com/app\t(devel)\t\ndep\tgolang.org/x/sys\tv0.1.0\th1:abc=\ndep\tgithub.com/a/b\tv1.0.0\th1:x=\n=>\tgithub.com/fork/b\tv1.0.1\th1:y=\n");
        data.extend(GO_INFO_END);
        let (main, mods) = go_modules(&data).unwrap();
        assert_eq!(main.as_deref(), Some("example.com/app"));
        assert_eq!(mods.len(), 2);
        assert_eq!(mods[0].purl(), "pkg:golang/golang.org/x/sys@v0.1.0");
        assert_eq!((mods[1].name.as_str(), mods[1].version.as_str()), ("github.com/fork/b", "v1.0.1"));
    }

    /// A minimal 64-bit little-endian ELF file with one named section.
    pub fn elf_with_section(name: &str, contents: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; 64];
        d[..4].copy_from_slice(b"\x7fELF");
        d[4] = 2;
        d[5] = 1;
        d[0x10] = 3;
        let body_off = d.len();
        d.extend(contents);
        let strtab_off = d.len();
        let mut strtab = vec![0u8];
        let name_off = strtab.len();
        strtab.extend(name.as_bytes());
        strtab.push(0);
        let shstr_name = strtab.len();
        strtab.extend(b".shstrtab\0");
        d.extend(&strtab);
        let shoff = d.len();
        let sh = |name: usize, ty: u32, off: usize, size: usize| {
            let mut h = vec![0u8; 64];
            h[..4].copy_from_slice(&(name as u32).to_le_bytes());
            h[4..8].copy_from_slice(&ty.to_le_bytes());
            h[0x18..0x20].copy_from_slice(&(off as u64).to_le_bytes());
            h[0x20..0x28].copy_from_slice(&(size as u64).to_le_bytes());
            h
        };
        d.extend(sh(0, 0, 0, 0));
        d.extend(sh(name_off, 1, body_off, contents.len()));
        d.extend(sh(shstr_name, 3, strtab_off, strtab.len()));
        d[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        d[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        d[0x3c..0x3e].copy_from_slice(&3u16.to_le_bytes());
        d[0x3e..0x40].copy_from_slice(&2u16.to_le_bytes());
        d
    }

    #[test]
    fn auditable_section() {
        use std::io::Write;
        let json = br#"{"packages":[{"name":"app","version":"0.1.0","source":"local","root":true},{"name":"serde","version":"1.0.200","source":"crates.io"},{"name":"cc","version":"1.0.0","source":"crates.io","kind":"build"}]}"#;
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(json).unwrap();
        let elf = elf_with_section(".dep-v0", &z.finish().unwrap());
        let crates = auditable_crates(&elf).unwrap();
        assert_eq!(crates.len(), 1);
        assert_eq!(crates[0].purl(), "pkg:cargo/serde@1.0.200");
        assert!(section(&elf, ".missing").is_none());
    }
}
