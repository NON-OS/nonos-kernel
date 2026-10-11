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

use alloc::vec::Vec;

use super::put::{put_str, put_u16};
use crate::browser::shell::bookmarks::MAX_BOOKMARKS;
use crate::browser::shell::types::Bookmark;

pub const MAGIC: [u8; 4] = *b"NBR1";
pub const VERSION: u8 = 1;
/// The reader settings a record holds until the reader keeps its own:
/// theme 0, size 1, width 1, reading time shown.
pub const READER_DEFAULT: [u8; 4] = [0, 1, 1, 1];

/// What the browser keeps across runs.
#[derive(Default)]
pub struct Persisted {
    pub bookmarks: Vec<Bookmark>,
}

/// `p` as a record: magic, version, the bookmarks section (a `u16` count,
/// then url, title and `i64` starred time each), the tab groups section (a
/// `u16` count, then id, colour and name each), and four reader setting
/// bytes. This build keeps no groups or reader settings, so it writes none
/// and `READER_DEFAULT`.
pub fn encode(p: &Persisted) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    let marks = &p.bookmarks[..p.bookmarks.len().min(MAX_BOOKMARKS)];
    put_u16(&mut out, marks.len() as u16);
    for b in marks {
        put_str(&mut out, &b.url);
        put_str(&mut out, &b.title);
        out.extend_from_slice(&b.at_ms.to_le_bytes());
    }
    put_u16(&mut out, 0);
    out.extend_from_slice(&READER_DEFAULT);
    out
}
