//! The Nix language: parser, scope-resolving compiler and lazy evaluator.

pub mod ast;
pub mod astcache;
pub mod builtins;
pub mod compile;
pub mod derivation;
pub mod error;
pub mod eval;
pub mod fetch;
pub mod flake;
pub mod parser;
pub mod print;
pub mod toml;
pub mod value;
pub mod vm;
pub mod xml;

pub use error::RenderOptions;
pub use eval::{Eval, EvalError, Options, R};
pub use value::Value;
