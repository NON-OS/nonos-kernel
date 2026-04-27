pub mod arena;
pub mod convert;
pub mod dirty;
pub mod mutate;
pub mod node;
pub mod query;
pub mod traverse;

#[cfg(test)]
mod tests_arena;
#[cfg(test)]
mod tests_query;

pub use arena::DomArena;
pub use convert::document_to_arena;
pub use mutate::{append_child, insert_before, remove_child};
pub use node::{DomNode, DomNodeType, NodeId};
pub use query::{get_element_by_id, get_elements_by_class_name, get_elements_by_tag_name};
pub use query::{query_selector, query_selector_all};
