pub mod node;
pub mod arena;
pub mod mutate;
pub mod traverse;
pub mod query;
pub mod convert;
pub mod dirty;

#[cfg(test)]
mod tests_arena;
#[cfg(test)]
mod tests_query;

pub use node::{NodeId, DomNode, DomNodeType};
pub use arena::DomArena;
pub use mutate::{append_child, remove_child, insert_before};
pub use query::{get_element_by_id, get_elements_by_class_name, get_elements_by_tag_name};
pub use query::{query_selector, query_selector_all};
pub use convert::document_to_arena;
