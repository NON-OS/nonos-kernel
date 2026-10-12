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
use alloc::vec::Vec;

use super::title::title_of;
use super::walk::{blocks, root};
use crate::browser::dom::Dom;
use crate::browser::shell::site_label::site;
use crate::browser::shell::visits::host_of;

pub const MAX_PARAS: usize = 400;
const WORDS_PER_MINUTE: u32 = 220;

/// A page cut down to what reading it needs.
pub struct Article {
    pub title: String,
    pub site: String,
    pub paras: Vec<Para>,
    pub words: u32,
}

pub enum Para {
    Heading(String),
    Text(String),
    Quote(String),
}

impl Para {
    pub fn text(&self) -> &str {
        match self {
            Para::Heading(s) | Para::Text(s) | Para::Quote(s) => s,
        }
    }
}

/// The readable part of `dom`, shown at `address`: its title, the site the
/// address names (the document's own host when there is no address), and
/// the headings, paragraphs and quotes of its first `article` or `main`, or
/// of the whole document when it has neither.
pub fn extract(dom: &Dom, address: &str) -> Article {
    let mut paras = blocks(dom, root(dom));
    paras.retain(|p| p.text().split_whitespace().nth(1).is_some());
    paras.truncate(MAX_PARAS);
    let words = paras.iter().map(|p| p.text().split_whitespace().count() as u32).sum();
    let site = match site(address) {
        s if s.is_empty() => host_of(&dom.base),
        s => s,
    };
    Article { title: title_of(dom).unwrap_or_default(), site, paras, words }
}

/// Whole minutes it takes to read `words`, never less than one.
pub fn minutes(words: u32) -> u32 {
    (words / WORDS_PER_MINUTE).max(1)
}
