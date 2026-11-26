//! Linux sandbox: the builder runs as PID 1 of fresh user, mount, PID,
//! IPC, UTS and (except for fixed-output derivations) network namespaces,
//! inside a chroot assembled from bind mounts of its input closure, like
//! Nix's. Inside, it is `nixbld` (uid 1000, gid 100), which the user
//! namespace maps to the invoking user, so no privileges are needed.
//!
//! The parent prepares the chroot's directory tree and every string the
//! child needs; the forked child then only makes system calls, since
//! allocating after `fork` in a multi-threaded process can deadlock.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use oxnix_core::StorePath;

use super::Spec;
use crate::build::BuildOptions;
use crate::{fsutil, Result, Store};

/// User and group of the builder inside the sandbox.
const SANDBOX_UID: u32 = 1000;
const SANDBOX_GID: u32 = 100;

/// Device nodes bind-mounted from the host unless `/dev` itself is a
/// sandbox path.
const DEVICES: &[&str] = &["/dev/full", "/dev/null", "/dev/random", "/dev/tty", "/dev/urandom", "/dev/zero"];

struct Bind {
    source: CString,
    target: CString,
    /// Remount flags making the bind read-only while keeping the flags the
    /// kernel locks for mounts inherited from a more privileged namespace;
    /// `None` leaves the bind writable.
    read_only: Option<libc::c_ulong>,
}

/// Everything the child needs, prepared before forking.
struct Plan {
    unshare_flags: libc::c_int,
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    root: CString,
    binds: Vec<Bind>,
    proc_dir: CString,
    shm_dir: Option<CString>,
    shm_options: CString,
    pts_dir: Option<CString>,
    private_network: bool,
    build_dir: CString,
}

pub(crate) struct Chroot {
    root: PathBuf,
    /// The build directory as seen inside, `sandbox-build-dir`.
    pub build_dir: String,
    plan: std::sync::Arc<Plan>,
}

fn cstr(p: impl AsRef<Path>) -> Result<CString> {
    CString::new(p.as_ref().as_os_str().as_bytes()).map_err(|_| format!("path '{}' contains a NUL byte", p.as_ref().display()))
}

fn io_err(what: &str, p: &Path) -> impl FnOnce(io::Error) -> String {
    let msg = format!("{what} '{}'", p.display());
    move |e| format!("{msg}: {e}")
}

/// Mount flags the kernel requires a read-only remount of a bind of `p`
/// to keep.
fn locked_flags(p: &Path) -> Result<libc::c_ulong> {
    let c = cstr(p)?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is NUL-terminated and `st` is a valid out-pointer.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(format!("getting mount flags of '{}': {}", p.display(), io::Error::last_os_error()));
    }
    let f = st.f_flag;
    let mut m = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY;
    for (st_flag, ms_flag) in [
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
        (libc::ST_NOATIME, libc::MS_NOATIME),
        (libc::ST_NODIRATIME, libc::MS_NODIRATIME),
        (libc::ST_RELATIME, libc::MS_RELATIME),
    ] {
        if f & st_flag != 0 {
            m |= ms_flag;
        }
    }
    Ok(m)
}

/// Creates the mount point for `source` at `target` inside the chroot, or
/// copies it when it is a symlink. Returns whether `source` must be
/// bind-mounted.
fn make_target(source: &Path, target: &Path, optional: bool) -> Result<bool> {
    let md = match fs::symlink_metadata(source) {
        Ok(m) => m,
        Err(e) if optional && e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("getting attributes of path '{}': {e}", source.display())),
    };
    if let Some(dir) = target.parent() {
        fs::create_dir_all(dir).map_err(io_err("creating", dir))?;
    }
    if target.symlink_metadata().is_ok() {
        return Ok(!md.file_type().is_symlink());
    }
    if md.file_type().is_symlink() {
        let to = fs::read_link(source).map_err(io_err("reading link", source))?;
        symlink(to, target).map_err(io_err("creating", target))?;
        Ok(false)
    } else if md.is_dir() {
        fs::create_dir(target).map_err(io_err("creating", target))?;
        Ok(true)
    } else {
        fs::File::create(target).map_err(io_err("creating", target))?;
        Ok(true)
    }
}

fn write(p: &Path, contents: &str) -> Result<()> {
    fs::write(p, contents).map_err(io_err("writing", p))
}

impl Chroot {
    /// Builds the chroot's directory tree at `root` (Nix places it next to
    /// the derivation, `<drv>.chroot`, so outputs can be renamed into the
    /// store) and plans the mounts.
    pub fn prepare(root: PathBuf, spec: &Spec, store_dir: &str, top: &Path, opts: &BuildOptions) -> Result<Chroot> {
        let build_dir = opts.sandbox_build_dir.clone();
        // The build directory is mounted over that part of the chroot.
        if store_dir == build_dir || store_dir.strip_prefix(&build_dir).is_some_and(|r| r.starts_with('/')) {
            return Err(format!("'sandbox-build-dir' ({build_dir}) must not contain the store directory '{store_dir}'"));
        }
        fsutil::remove_all(&root)?;
        fs::create_dir(&root).map_err(io_err("creating", &root))?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).map_err(io_err("setting permissions of", &root))?;
        let inside = |p: &str| root.join(p.trim_start_matches('/'));

        // A world-writable /tmp, since many builders ignore $TMPDIR.
        let tmp = inside("/tmp");
        fs::create_dir(&tmp).map_err(io_err("creating", &tmp))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o1777)).map_err(io_err("setting permissions of", &tmp))?;

        let etc = inside("/etc");
        fs::create_dir(&etc).map_err(io_err("creating", &etc))?;
        write(
            &etc.join("passwd"),
            &format!(
                "root:x:0:0:Nix build user:{build_dir}:/noshell\nnixbld:x:{SANDBOX_UID}:{SANDBOX_GID}:Nix build user:{build_dir}:/noshell\nnobody:x:65534:65534:Nobody:/:/noshell\n"
            ),
        )?;
        write(&etc.join("group"), &format!("root:x:0:\nnixbld:!:{SANDBOX_GID}:\nnogroup:x:65534:\n"))?;
        if !spec.network {
            write(&etc.join("hosts"), "127.0.0.1 localhost\n::1 localhost\n")?;
        }

        let store = inside(store_dir);
        fs::create_dir_all(&store).map_err(io_err("creating", &store))?;
        fs::set_permissions(&store, fs::Permissions::from_mode(0o1775)).map_err(io_err("setting permissions of", &store))?;

        let mut binds = Vec::new();
        let has = |p: &str| spec.paths.contains_key(p);

        let build_target = inside(&build_dir);
        fs::create_dir_all(&build_target).map_err(io_err("creating", &build_target))?;
        binds.push(Bind { source: cstr(top)?, target: cstr(&build_target)?, read_only: None });

        let dev = inside("/dev");
        fs::create_dir_all(&dev).map_err(io_err("creating", &dev))?;
        let mut shm_dir = None;
        let mut pts_dir = None;
        if !has("/dev") {
            for d in DEVICES {
                let t = inside(d);
                if make_target(Path::new(d), &t, true)? {
                    binds.push(Bind { source: cstr(d)?, target: cstr(&t)?, read_only: None });
                }
            }
            if opts.system_features.iter().any(|f| f == "kvm") {
                let t = inside("/dev/kvm");
                if make_target(Path::new("/dev/kvm"), &t, true)? {
                    binds.push(Bind { source: cstr("/dev/kvm")?, target: cstr(&t)?, read_only: None });
                }
            }
            for (link, to) in [
                ("fd", "/proc/self/fd"),
                ("stdin", "/proc/self/fd/0"),
                ("stdout", "/proc/self/fd/1"),
                ("stderr", "/proc/self/fd/2"),
            ] {
                symlink(to, dev.join(link)).map_err(io_err("creating", &dev.join(link)))?;
            }
            if !has("/dev/shm") {
                let d = dev.join("shm");
                fs::create_dir(&d).map_err(io_err("creating", &d))?;
                shm_dir = Some(cstr(&d)?);
            }
            if !has("/dev/pts") && Path::new("/dev/pts/ptmx").exists() {
                let d = dev.join("pts");
                fs::create_dir(&d).map_err(io_err("creating", &d))?;
                symlink("/dev/pts/ptmx", dev.join("ptmx")).map_err(io_err("creating", &dev.join("ptmx")))?;
                pts_dir = Some(cstr(&d)?);
            }
        }
        let proc_dir = inside("/proc");
        fs::create_dir(&proc_dir).map_err(io_err("creating", &proc_dir))?;

        // Sorted by target, so a directory is mounted before paths below it.
        for (target, p) in &spec.paths {
            let t = inside(target);
            let source = Path::new(&p.source);
            if make_target(source, &t, p.optional)? {
                let read_only = if target.starts_with("/dev") { None } else { Some(locked_flags(source)?) };
                binds.push(Bind { source: cstr(source)?, target: cstr(&t)?, read_only });
            }
        }

        // SAFETY: getuid and getgid cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let mut unshare_flags =
            libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
        if !spec.network {
            unshare_flags |= libc::CLONE_NEWNET;
        }
        let plan = Plan {
            unshare_flags,
            uid_map: format!("{SANDBOX_UID} {uid} 1").into_bytes(),
            gid_map: format!("{SANDBOX_GID} {gid} 1").into_bytes(),
            root: cstr(&root)?,
            binds,
            proc_dir: cstr(&proc_dir)?,
            shm_dir,
            shm_options: CString::new(format!("size={}", opts.sandbox_dev_shm_size)).map_err(|_| "bad sandbox-dev-shm-size")?,
            pts_dir,
            private_network: !spec.network,
            build_dir: cstr(&build_dir)?,
        };
        Ok(Chroot { root, build_dir, plan: std::sync::Arc::new(plan) })
    }

    /// A command that enters the sandbox between `fork` and `exec`.
    pub fn command(&self, builder: &str, args: &[String]) -> Command {
        let mut c = Command::new(builder);
        c.args(args);
        let plan = self.plan.clone();
        // SAFETY: `enter` only makes system calls on memory prepared by the
        // parent, which is async-signal-safe.
        unsafe {
            c.pre_exec(move || enter(&plan));
        }
        c
    }

    pub fn collect_outputs(&self, store: &Store, outputs: &[&StorePath]) -> Result<()> {
        for p in outputs {
            let inside = self.root.join(store.dir.print(p).trim_start_matches('/'));
            if inside.symlink_metadata().is_ok() {
                let real = store.real_path(p);
                fsutil::remove_all(&real)?;
                fs::rename(&inside, &real).map_err(io_err("moving output", &inside))?;
            }
        }
        Ok(())
    }

    /// The mounts live only in the build's mount namespace, which is gone
    /// once its processes are, so only empty mount points remain here.
    pub fn cleanup(&self) -> Result<()> {
        fsutil::remove_all(&self.root)
    }
}

/// Writes `msg`, `arg` and the current `errno` to stderr (the build log)
/// without allocating, and returns the error.
fn fail(msg: &[u8], arg: Option<&CString>) -> io::Error {
    let err = io::Error::last_os_error();
    let mut buf = [0u8; 12];
    let mut n = err.raw_os_error().unwrap_or(0).unsigned_abs();
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let put = |b: &[u8]| {
        // SAFETY: writes a valid buffer to fd 2; failure is ignored.
        unsafe { libc::write(2, b.as_ptr().cast(), b.len()) };
    };
    put(b"oxnix: setting up the build sandbox: ");
    put(msg);
    if let Some(a) = arg {
        put(b" '");
        put(a.as_bytes());
        put(b"'");
    }
    put(b": errno ");
    put(&buf[i..]);
    put(b"\n");
    err
}

fn check(r: libc::c_int, msg: &[u8], arg: Option<&CString>) -> io::Result<()> {
    if r == -1 {
        Err(fail(msg, arg))
    } else {
        Ok(())
    }
}

/// Writes `data` to the NUL-terminated `path`, leaving `errno` set on
/// failure.
fn write_proc(path: &[u8], data: &[u8]) -> bool {
    // SAFETY: `path` is NUL-terminated and `data` a valid buffer; errno is
    // restored after close.
    unsafe {
        let fd = libc::open(path.as_ptr().cast(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd == -1 {
            return false;
        }
        let ok = libc::write(fd, data.as_ptr().cast(), data.len()) == data.len() as isize;
        let errno = *libc::__errno_location();
        libc::close(fd);
        *libc::__errno_location() = errno;
        ok
    }
}

fn write_map(path: &[u8], data: &[u8]) -> io::Result<()> {
    if write_proc(path, data) {
        Ok(())
    } else {
        Err(fail(&path[..path.len() - 1], None))
    }
}

/// Enters the namespaces and the chroot. Runs in the forked child; the
/// builder is exec'd in a grandchild that is PID 1 of the new PID
/// namespace, while the child waits for it and passes on its status.
fn enter(plan: &Plan) -> io::Result<()> {
    // SAFETY: plain system calls on buffers owned by `plan`.
    unsafe {
        check(libc::unshare(plan.unshare_flags), b"creating namespaces", None)?;
        write_map(b"/proc/self/setgroups\0", b"deny")?;
        write_map(b"/proc/self/uid_map\0", &plan.uid_map)?;
        write_map(b"/proc/self/gid_map\0", &plan.gid_map)?;

        let pid = libc::fork();
        check(pid, b"forking", None)?;
        if pid > 0 {
            relay(pid);
        }

        // Dies with the relaying parent, which takes the whole PID
        // namespace down when the build is killed.
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        setup_root(plan)
    }
}

/// Waits for the builder and exits like it. Closes every descriptor first
/// so `spawn` returns once the builder has been exec'd and the log pipes
/// close when the build's processes are gone.
unsafe fn relay(pid: libc::pid_t) -> ! {
    if libc::syscall(libc::SYS_close_range, 0u32, u32::MAX, 0u32) != 0 {
        for fd in 0..1024 {
            libc::close(fd);
        }
    }
    let mut status = 0;
    while libc::waitpid(pid, &mut status, 0) == -1 {
        if *libc::__errno_location() != libc::EINTR {
            libc::_exit(1);
        }
    }
    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        libc::signal(sig, libc::SIG_DFL);
        libc::kill(libc::getpid(), sig);
        libc::_exit(128 + sig);
    }
    libc::_exit(libc::WEXITSTATUS(status))
}

unsafe fn setup_root(plan: &Plan) -> io::Result<()> {
    let null = std::ptr::null::<libc::c_char>();
    // Keep the mounts below from propagating back to the host.
    check(
        libc::mount(null, c"/".as_ptr(), null, libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()),
        b"making / private",
        None,
    )?;
    // pivot_root needs the new root to be a mount point.
    check(
        libc::mount(plan.root.as_ptr(), plan.root.as_ptr(), null, libc::MS_BIND, std::ptr::null()),
        b"bind-mounting the chroot onto itself",
        Some(&plan.root),
    )?;
    for b in &plan.binds {
        check(
            libc::mount(b.source.as_ptr(), b.target.as_ptr(), null, libc::MS_BIND | libc::MS_REC, std::ptr::null()),
            b"bind-mounting",
            Some(&b.source),
        )?;
        if let Some(flags) = b.read_only {
            check(
                libc::mount(null, b.target.as_ptr(), null, flags, std::ptr::null()),
                b"making read-only",
                Some(&b.source),
            )?;
        }
    }
    check(
        libc::mount(c"none".as_ptr(), plan.proc_dir.as_ptr(), c"proc".as_ptr(), 0, std::ptr::null()),
        b"mounting /proc",
        None,
    )?;
    if let Some(d) = &plan.shm_dir {
        check(
            libc::mount(
                c"none".as_ptr(),
                d.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                plan.shm_options.as_ptr().cast(),
            ),
            b"mounting /dev/shm",
            None,
        )?;
    }
    if let Some(d) = &plan.pts_dir {
        check(
            libc::mount(
                c"none".as_ptr(),
                d.as_ptr(),
                c"devpts".as_ptr(),
                0,
                c"newinstance,mode=0620".as_ptr().cast(),
            ),
            b"mounting /dev/pts",
            None,
        )?;
    }

    check(libc::sethostname(c"localhost".as_ptr(), 9), b"setting the host name", None)?;
    check(libc::setdomainname(c"(none)".as_ptr(), 6), b"setting the domain name", None)?;

    if plan.private_network {
        // The new network namespace has only a loopback device, down.
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        check(fd, b"creating a socket", None)?;
        let mut ifr: libc::ifreq = std::mem::zeroed();
        ifr.ifr_name[0] = b'l' as libc::c_char;
        ifr.ifr_name[1] = b'o' as libc::c_char;
        ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_LOOPBACK | libc::IFF_RUNNING) as libc::c_short;
        let r = libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &ifr);
        libc::close(fd);
        check(r, b"bringing up the loopback interface", None)?;
    }

    check(libc::chdir(plan.root.as_ptr()), b"entering the chroot", Some(&plan.root))?;
    check(libc::mkdir(c"real-root".as_ptr(), 0o500), b"creating real-root", None)?;
    check(
        libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c"real-root".as_ptr()) as libc::c_int,
        b"pivot_root",
        Some(&plan.root),
    )?;
    check(libc::chroot(c".".as_ptr()), b"chroot", None)?;
    check(libc::umount2(c"real-root".as_ptr(), libc::MNT_DETACH), b"unmounting the host root", None)?;
    check(libc::rmdir(c"real-root".as_ptr()), b"removing real-root", None)?;
    check(libc::chdir(plan.build_dir.as_ptr()), b"entering the build directory", Some(&plan.build_dir))?;
    Ok(())
}

/// Whether user namespaces (with the namespaces a build needs inside
/// them) can be created and entered here. Some kernels allow creating an
/// unprivileged user namespace but deny writing its ID maps, as Ubuntu's
/// AppArmor policy does, so the probe goes as far as a mount.
pub(crate) fn supported() -> bool {
    let flags = libc::CLONE_NEWUSER
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWNET;
    // SAFETY: getuid and getgid cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let uid_map = format!("{SANDBOX_UID} {uid} 1");
    let gid_map = format!("{SANDBOX_GID} {gid} 1");
    // SAFETY: the child only makes system calls on memory prepared before
    // the fork, then exits.
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            let ok = libc::unshare(flags) == 0
                && write_proc(b"/proc/self/setgroups\0", b"deny")
                && write_proc(b"/proc/self/uid_map\0", uid_map.as_bytes())
                && write_proc(b"/proc/self/gid_map\0", gid_map.as_bytes())
                && libc::mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) == 0;
            libc::_exit(if ok { 0 } else { 1 });
        }
        if pid < 0 {
            return false;
        }
        let mut status = 0;
        while libc::waitpid(pid, &mut status, 0) == -1 {
            if *libc::__errno_location() != libc::EINTR {
                return false;
            }
        }
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }
}
