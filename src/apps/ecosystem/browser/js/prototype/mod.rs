pub mod array_proto;
pub mod builtin_protos;
pub mod chain;
mod create;
pub mod number_proto;
pub mod string_proto;

#[cfg(test)]
mod tests;

pub use array_proto::populate as populate_array_proto;
pub use builtin_protos::BuiltinPrototypes;
pub use chain::{ProtoChain, ProtoObject};
pub use create::{create_with_proto, object_create};
pub use number_proto::populate as populate_number_proto;
pub use string_proto::populate as populate_string_proto;
