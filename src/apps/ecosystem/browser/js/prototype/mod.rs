pub mod chain;
mod create;
pub mod builtin_protos;
mod string_proto;
mod array_proto;
mod number_proto;

#[cfg(test)]
mod tests;

pub use chain::{ProtoChain, ProtoObject};
pub use create::{create_with_proto, object_create};
pub use builtin_protos::BuiltinPrototypes;
