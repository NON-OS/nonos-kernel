extern crate alloc;
use super::match_node::NodeInfo;
use super::types::{AttributeOp, AttributeSelector};

pub fn matches_attribute(node: &NodeInfo, sel: &AttributeSelector) -> bool {
    let val = node.attributes.iter().find(|(n, _)| n == &sel.name).map(|(_, v)| v.as_str());
    match sel.op {
        AttributeOp::Exists => val.is_some(),
        AttributeOp::Equals => val == sel.value.as_deref(),
        AttributeOp::Contains => {
            val.zip(sel.value.as_deref()).map_or(false, |(v, s)| v.contains(s))
        }
        AttributeOp::StartsWith => {
            val.zip(sel.value.as_deref()).map_or(false, |(v, s)| v.starts_with(s))
        }
        AttributeOp::EndsWith => {
            val.zip(sel.value.as_deref()).map_or(false, |(v, s)| v.ends_with(s))
        }
        AttributeOp::DashMatch => val
            .zip(sel.value.as_deref())
            .map_or(false, |(v, s)| v == s || v.starts_with(&alloc::format!("{}-", s))),
    }
}
