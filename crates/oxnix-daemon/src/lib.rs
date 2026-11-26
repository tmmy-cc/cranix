//! The Nix worker protocol: an `oxnix daemon` serving a store to Nix
//! clients, a client for `nix-daemon` (local socket or `ssh-ng://`), and
//! remote builders on top of that client.

pub mod proto;
pub mod server;
pub mod wire;
