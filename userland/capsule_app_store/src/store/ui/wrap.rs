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
//! Breaking a description to the width it has.
//! Kept over the toolkit's `text::wrap`, which sums each word's width where
//! this measures the joined line, and splits at any whitespace where this
//! splits at spaces: their breaks can differ by a word at the edge.

use alloc::vec::Vec;

use nonos_toolkit::widgets::text::width;

use super::bytes::as_str;

pub fn wrap(text: &[u8], room: u32, px: f32) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut line: Vec<u8> = Vec::new();
    for word in text.split(|b| *b == b' ').filter(|w| !w.is_empty()) {
        let mut candidate = line.clone();
        if !candidate.is_empty() {
            candidate.push(b' ');
        }
        candidate.extend_from_slice(word);
        if width(as_str(&candidate), px) > room && !line.is_empty() {
            out.push(core::mem::take(&mut line));
            line.extend_from_slice(word);
        } else {
            line = candidate;
        }
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}
