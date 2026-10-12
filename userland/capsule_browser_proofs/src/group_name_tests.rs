// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! Renaming a tab group: trimmed, held to its length, and refused for a
//! blank name or a group the window does not hold.

use crate::browser::shell::groups::{create, rename, MAX_NAME};
use crate::browser::shell::kept::Group;

fn made(n: usize) -> Vec<Group> {
    let mut g = Vec::new();
    for _ in 0..n {
        create(&mut g).unwrap();
    }
    g
}

#[test]
fn rename_trims_and_limits() {
    let mut g = made(1);
    assert!(rename(&mut g, 0, "  Travel  "));
    assert_eq!(g[0].name, "Travel");
    assert!(rename(&mut g, 0, &"x".repeat(50)));
    assert_eq!(g[0].name.chars().count(), MAX_NAME);
    assert!(rename(&mut g, 0, &"\u{1f600}".repeat(40)));
    assert_eq!(g[0].name.chars().count(), MAX_NAME);
    let spaced = format!("{} tail", "a".repeat(MAX_NAME - 1));
    assert!(rename(&mut g, 0, &spaced));
    assert_eq!(g[0].name, "a".repeat(MAX_NAME - 1));
}

#[test]
fn rename_rejects_blank_names_and_unknown_ids() {
    let mut g = made(1);
    assert!(!rename(&mut g, 0, ""));
    assert!(!rename(&mut g, 0, " \t\n "));
    assert!(!rename(&mut g, 4, "Real"));
    assert_eq!(g[0].name, "Group 1");
}
