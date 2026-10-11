// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! Records for the saved-state codec tests.

use crate::browser::shell::kept::{Group, ReaderPrefs};
use crate::browser::shell::store::codec::{MAGIC, VERSION};
use crate::browser::shell::store::Persisted;
use crate::browser::shell::types::Bookmark;

pub const MAX_STR: usize = 2048;

pub fn mark(url: &str, title: &str, at_ms: i64) -> Bookmark {
    Bookmark { url: url.into(), title: title.into(), at_ms }
}

pub fn full() -> Persisted {
    Persisted {
        bookmarks: vec![mark("https://a.com/x", "A \u{00e9}", -3), mark("https://b.org/", "", 9)],
        groups: vec![Group { id: 4, name: "Work".into(), color: 3 }],
        reader: ReaderPrefs { theme: 2, size: 4, width: 0, show_time: false },
    }
}

fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u16).to_le_bytes());
    out.extend_from_slice(s);
}

pub fn record(marks: &[(&[u8], &[u8])], groups: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.push(VERSION);
    out.extend_from_slice(&(marks.len() as u16).to_le_bytes());
    for (url, title) in marks {
        put_str(&mut out, url);
        put_str(&mut out, title);
        out.extend_from_slice(&7i64.to_le_bytes());
    }
    out.extend_from_slice(&(groups.len() as u16).to_le_bytes());
    for (id, name) in groups {
        out.extend_from_slice(&[*id, 1]);
        put_str(&mut out, name);
    }
    out.extend_from_slice(&[1, 2, 1, 1]);
    out
}
