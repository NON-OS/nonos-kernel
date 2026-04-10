mod types;
mod specificity;
pub mod match_node;
pub mod match_attr;

pub use types::{Selector, SimpleSelector, AttributeSelector, AttributeOp};
pub use specificity::Specificity;
pub use match_node::matches_selector;
pub use match_attr::matches_attribute;
