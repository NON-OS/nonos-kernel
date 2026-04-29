mod binding;
pub mod scope_chain;
pub mod this_binding;

#[cfg(test)]
mod tests;

pub use binding::{declare_binding, BindingKind};
pub use scope_chain::{LexicalScope, ScopeChain};
pub use this_binding::{resolve_this, ThisBinding};
