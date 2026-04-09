mod types;
mod specificity;
pub mod match_node;
mod match_attr;

pub use types::Selector;
pub use specificity::Specificity;
pub use match_node::matches_selector;
