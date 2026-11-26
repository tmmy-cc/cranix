//! Serves a directory as an HTTP binary cache that accepts uploads:
//! `cargo run --example cache-server -- ROOT [PORT]`. Prints its URL and
//! runs until killed. Used by `tests/http-cache.sh`.

#[path = "../tests/cache_server/mod.rs"]
mod cache_server;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(root) = args.first() else {
        eprintln!("usage: cache-server ROOT [PORT]");
        std::process::exit(1);
    };
    let port = args.get(1).map_or(0, |p| p.parse().expect("PORT must be a number"));
    let server = cache_server::CacheServer::start_on(std::path::Path::new(root), port);
    println!("{}", server.url);
    loop {
        std::thread::park();
    }
}
