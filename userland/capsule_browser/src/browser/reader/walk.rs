// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::extract::{Para, MAX_PARAS};
use crate::browser::dom::node::{Node, NodeKind};
use crate::browser::dom::Dom;

const SKIP: [&str; 10] =
    ["script", "style", "nav", "header", "footer", "aside", "form", "noscript", "svg", "button"];

fn element(node: &Node, tags: &[&str]) -> bool {
    node.kind == NodeKind::Element && tags.contains(&node.tag.as_str())
}

/// The first `article` or `main` element, else the document itself.
pub fn root(dom: &Dom) -> usize {
    let mut stack = vec![0usize];
    while let Some(id) = stack.pop() {
        let Some(node) = dom.nodes.get(id) else { continue };
        if element(node, &["article", "main"]) {
            return id;
        }
        stack.extend(node.children.iter().rev().copied());
    }
    0
}

/// The text blocks under `from` in document order, skipping the subtrees
/// that are navigation, chrome or code rather than reading matter.
pub fn blocks(dom: &Dom, from: usize) -> Vec<Para> {
    let (mut out, mut stack) = (Vec::new(), vec![from]);
    while let Some(id) = stack.pop() {
        let Some(node) = dom.nodes.get(id) else { continue };
        if element(node, &SKIP) {
            continue;
        }
        let text = || collapsed(dom, id);
        match (node.kind, node.tag.as_str()) {
            (NodeKind::Element, "h2" | "h3") => out.push(Para::Heading(text())),
            (NodeKind::Element, "p" | "li") => out.push(Para::Text(text())),
            (NodeKind::Element, "blockquote") => out.push(Para::Quote(text())),
            _ => stack.extend(node.children.iter().rev().copied()),
        }
        if out.len() >= 4 * MAX_PARAS {
            break;
        }
    }
    out
}

/// Every text node under `id` outside the skipped subtrees, joined with
/// runs of whitespace folded to one space.
fn collapsed(dom: &Dom, id: usize) -> String {
    let (mut words, mut stack): (Vec<&str>, _) = (Vec::new(), vec![id]);
    while let Some(i) = stack.pop() {
        let Some(node) = dom.nodes.get(i) else { continue };
        match node.kind {
            NodeKind::Text => words.extend(node.text.split_whitespace()),
            _ if element(node, &SKIP) => {}
            _ => stack.extend(node.children.iter().rev().copied()),
        }
    }
    words.join(" ")
}
