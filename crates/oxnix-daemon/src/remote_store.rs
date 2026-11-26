//! The operations remote building and `--store URI` need, over either a
//! worker protocol connection (`daemon`, `unix://`, `ssh-ng://`) or a
//! serve protocol one (`ssh://`).

use std::collections::BTreeSet;
use std::io::{self, Write};

use oxnix_core::{Derivation, StoreDir, StorePath};
use oxnix_store::PathInfo;

use crate::client::{ClientOptions, Connection, LogOptions, StoreUri, UriKind};
use crate::proto::{BuildResult, DerivedPath};
use crate::serve::ServeConnection;

pub type Result<T> = std::result::Result<T, String>;

/// Writes the NAR of a path being copied.
pub type NarOf<'a> = dyn Fn(&PathInfo, &mut dyn Write) -> io::Result<()> + Sync + 'a;

pub trait RemoteStore: Send {
    fn store_dir(&self) -> &StoreDir;
    fn set_store_dir(&mut self, sd: StoreDir);
    fn set_log(&mut self, log: LogOptions);
    fn set_options(&mut self, opts: &ClientOptions) -> Result<()>;
    fn query_valid_paths(&mut self, ps: &BTreeSet<StorePath>) -> Result<BTreeSet<StorePath>>;
    fn query_path_info(&mut self, p: &StorePath) -> Result<Option<PathInfo>>;
    /// Adds paths given in dependency order.
    fn add_paths(&mut self, infos: &[PathInfo], nar_of: &NarOf<'_>) -> Result<()>;
    fn nar_from_path(&mut self, p: &StorePath, out: &mut dyn Write) -> Result<()>;
    fn build_derivation(&mut self, drv_path: &StorePath, drv: &Derivation) -> Result<BuildResult>;
    fn build_paths(&mut self, targets: &[DerivedPath]) -> Result<Vec<(DerivedPath, BuildResult)>>;
    /// Registers a GC root on the remote side where the protocol allows.
    fn add_indirect_root(&mut self, link: &str) -> Result<()>;
}

pub fn open(uri: &StoreUri) -> Result<Box<dyn RemoteStore>> {
    Ok(match uri.kind {
        UriKind::Ssh { .. } => Box::new(ServeConnection::open(uri)?),
        _ => Box::new(Connection::open(uri)?),
    })
}

impl RemoteStore for Connection {
    fn store_dir(&self) -> &StoreDir {
        &self.sd
    }
    fn set_store_dir(&mut self, sd: StoreDir) {
        self.sd = sd;
    }
    fn set_log(&mut self, log: LogOptions) {
        self.log = log;
    }
    fn set_options(&mut self, opts: &ClientOptions) -> Result<()> {
        Connection::set_options(self, opts)
    }
    fn query_valid_paths(&mut self, ps: &BTreeSet<StorePath>) -> Result<BTreeSet<StorePath>> {
        Connection::query_valid_paths(self, ps)
    }
    fn query_path_info(&mut self, p: &StorePath) -> Result<Option<PathInfo>> {
        Connection::query_path_info(self, p)
    }
    fn add_paths(&mut self, infos: &[PathInfo], nar_of: &NarOf<'_>) -> Result<()> {
        self.add_multiple_to_store(infos, nar_of, false)
    }
    fn nar_from_path(&mut self, p: &StorePath, out: &mut dyn Write) -> Result<()> {
        Connection::nar_from_path(self, p, out)
    }
    fn build_derivation(&mut self, drv_path: &StorePath, drv: &Derivation) -> Result<BuildResult> {
        Connection::build_derivation(self, drv_path, drv)
    }
    fn build_paths(&mut self, targets: &[DerivedPath]) -> Result<Vec<(DerivedPath, BuildResult)>> {
        self.build_paths_with_results(targets)
    }
    fn add_indirect_root(&mut self, link: &str) -> Result<()> {
        Connection::add_indirect_root(self, link)
    }
}

impl RemoteStore for ServeConnection {
    fn store_dir(&self) -> &StoreDir {
        &self.sd
    }
    fn set_store_dir(&mut self, sd: StoreDir) {
        self.sd = sd;
    }
    fn set_log(&mut self, log: LogOptions) {
        ServeConnection::set_log(self, log)
    }
    /// The serve protocol sends build settings with each build request.
    fn set_options(&mut self, opts: &ClientOptions) -> Result<()> {
        self.keep_failed = opts.keep_failed;
        Ok(())
    }
    fn query_valid_paths(&mut self, ps: &BTreeSet<StorePath>) -> Result<BTreeSet<StorePath>> {
        ServeConnection::query_valid_paths(self, ps)
    }
    fn query_path_info(&mut self, p: &StorePath) -> Result<Option<PathInfo>> {
        ServeConnection::query_path_info(self, p)
    }
    fn add_paths(&mut self, infos: &[PathInfo], nar_of: &NarOf<'_>) -> Result<()> {
        ServeConnection::add_paths(self, infos, nar_of)
    }
    fn nar_from_path(&mut self, p: &StorePath, out: &mut dyn Write) -> Result<()> {
        ServeConnection::nar_from_path(self, p, out)
    }
    fn build_derivation(&mut self, drv_path: &StorePath, drv: &Derivation) -> Result<BuildResult> {
        ServeConnection::build_derivation(self, drv_path, drv)
    }
    fn build_paths(&mut self, targets: &[DerivedPath]) -> Result<Vec<(DerivedPath, BuildResult)>> {
        ServeConnection::build_paths(self, targets)
    }
    /// `nix-store --serve` keeps no roots for its clients.
    fn add_indirect_root(&mut self, _link: &str) -> Result<()> {
        Ok(())
    }
}
