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

use crate::browser::dom::node::NodeKind;
use crate::browser::dom::Dom;

const CAP: usize = 80;

/// The first `<title>`, else the first `<h1>`, whitespace collapsed and cut
/// to 80 characters. None when both are missing or blank. The parser has
/// already resolved character references in both, so none are decoded here.
pub fn title_of(dom: &Dom) -> Option<String> {
    let titled = find(dom, "title").map(|id| own_text(dom, id));
    let raw = match titled.filter(|t| !t.trim().is_empty()) {
        Some(t) => t,
        None => deep_text(dom, find(dom, "h1")?),
    };
    let clean = capped(&raw);
    (!clean.is_empty()).then_some(clean)
}

fn capped(s: &str) -> String {
    let joined: Vec<&str> = s.split_whitespace().collect();
    joined.join(" ").chars().take(CAP).collect()
}

fn find(dom: &Dom, tag: &str) -> Option<usize> {
    let mut stack = vec![0usize];
    while let Some(id) = stack.pop() {
        let node = dom.nodes.get(id)?;
        if node.kind == NodeKind::Element && node.tag.eq_ignore_ascii_case(tag) {
            return Some(id);
        }
        stack.extend(node.children.iter().rev().copied());
    }
    None
}

fn own_text(dom: &Dom, id: usize) -> String {
    let kids = dom.nodes[id].children.iter().filter_map(|&c| dom.nodes.get(c));
    kids.filter(|n| n.kind == NodeKind::Text).map(|n| n.text.as_str()).collect()
}

fn deep_text(dom: &Dom, id: usize) -> String {
    let (mut out, mut stack) = (String::new(), vec![id]);
    while let Some(i) = stack.pop() {
        let Some(node) = dom.nodes.get(i) else { continue };
        if node.kind == NodeKind::Text {
            out.push_str(&node.text);
        } else if !matches!(node.tag.as_str(), "script" | "style") {
            stack.extend(node.children.iter().rev().copied());
        }
    }
    out
}
