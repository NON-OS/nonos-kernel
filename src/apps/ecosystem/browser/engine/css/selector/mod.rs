pub mod match_attr;
pub mod match_node;
mod specificity;
mod types;

pub use match_attr::matches_attribute;
pub use match_node::matches_selector;
pub use specificity::Specificity;
pub use types::{AttributeOp, AttributeSelector, Selector, SimpleSelector};
