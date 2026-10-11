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

use super::codec::{Persisted, MAGIC, READER_DEFAULT, VERSION};
use super::cursor::Cursor;
use crate::browser::shell::bookmarks::MAX_BOOKMARKS;
use crate::browser::shell::types::Bookmark;

/// The record in `b`, or the defaults when it is short, foreign or from a
/// newer build. Bookmarks past the cap are skipped and a non-UTF-8 one is
/// dropped. The groups and reader sections are checked whole and passed
/// over, as this build keeps neither.
pub fn decode(b: &[u8]) -> Persisted {
    read(&mut Cursor::new(b)).unwrap_or_default()
}

fn read(c: &mut Cursor) -> Option<Persisted> {
    if c.bytes(MAGIC.len())? != MAGIC {
        return None;
    }
    let version = c.u8()?;
    if version == 0 || version > VERSION {
        return None;
    }
    let mut bookmarks = Vec::new();
    for _ in 0..c.u16()? {
        let (url, title, at_ms) = (c.str()?, c.str()?, c.i64()?);
        if let (Some(url), Some(title), true) = (url, title, bookmarks.len() < MAX_BOOKMARKS) {
            bookmarks.push(Bookmark { url, title, at_ms });
        }
    }
    for _ in 0..c.u16()? {
        c.bytes(2)?;
        c.str()?;
    }
    c.bytes(READER_DEFAULT.len())?;
    Some(Persisted { bookmarks })
}
