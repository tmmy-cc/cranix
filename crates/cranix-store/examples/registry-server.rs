//! A fake GitLab and OCI package registry for tests:
//! `cargo run --example registry-server -- [READ_TOKEN WRITE_TOKEN]`.
//! Prints its address and runs until killed. Used by
//! `tests/registry-cache.sh`.

#[path = "../tests/registry_server/mod.rs"]
mod registry_server;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let server = registry_server::RegistryServer::start(args.first().map(String::as_str), args.get(1).map(String::as_str));
    println!("{}", server.addr);
    loop {
        std::thread::park();
    }
}
