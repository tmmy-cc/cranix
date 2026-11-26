//! The Nix worker protocol: an `oxnix daemon` serving a store to Nix
//! clients, a client for `nix-daemon` (local socket or `ssh-ng://`), and
//! remote builders on top of that client.

pub mod client;
pub mod machines;
pub mod proto;
pub mod remote_build;
pub mod server;
pub mod wire;
