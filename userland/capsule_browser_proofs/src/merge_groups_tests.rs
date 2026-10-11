// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! Merging this window's tab groups and reader settings with another
//! window's save: this window's groups first, removals kept out, within the
//! cap, and this window's reader settings kept.

use crate::browser::shell::kept::{Group, ReaderPrefs};
use crate::browser::shell::store::merge::{merge, Removed};
use crate::browser::shell::store::Persisted;

fn none() -> Removed<'static> {
    Removed { bookmarks: &[], groups: &[] }
}

fn grouped(ids: &[(u8, &str)]) -> Persisted {
    let groups = ids.iter().map(|&(id, n)| Group { id, name: n.into(), color: id }).collect();
    Persisted { groups, ..Default::default() }
}

#[test]
fn groups_union_with_this_window_first_and_removals_kept_out() {
    let disk = grouped(&[(0, "disk zero"), (1, "One"), (2, "Two")]);
    let mine = grouped(&[(0, "Mine"), (3, "Three")]);
    let p = merge(disk, mine, Removed { bookmarks: &[], groups: &[2] });
    let got: Vec<(u8, &str)> = p.groups.iter().map(|g| (g.id, g.name.as_str())).collect();
    assert_eq!(got, [(0, "Mine"), (3, "Three"), (1, "One")]);
}

#[test]
fn groups_hold_to_the_cap_and_the_reader_settings_are_mine() {
    let disk: Vec<(u8, &str)> = (0..8).map(|i| (i, "d")).collect();
    let mine = Persisted {
        reader: ReaderPrefs { theme: 2, ..Default::default() },
        ..grouped(&[(9, "m")])
    };
    let p = merge(grouped(&disk), mine, none());
    assert_eq!(p.groups.len(), 8);
    assert_eq!(p.groups[0].id, 9);
    assert_eq!(p.reader.theme, 2);
}
