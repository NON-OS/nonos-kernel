pub mod scope_chain;
mod binding;
pub mod this_binding;

#[cfg(test)]
mod tests;

pub use scope_chain::{LexicalScope, ScopeChain};
pub use binding::{BindingKind, declare_binding};
pub use this_binding::{ThisBinding, resolve_this};
