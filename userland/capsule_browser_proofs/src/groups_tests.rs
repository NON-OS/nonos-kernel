// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! Tab groups: created up to the cap under stable ids, cycled through in
//! order, and the tabs a group filter shows.

use crate::browser::shell::groups::{count, create, cycle, find, members, remove, MAX_GROUPS};
use crate::browser::shell::kept::Group;

fn ids(g: &[Group]) -> Vec<u8> {
    g.iter().map(|g| g.id).collect()
}

fn made(n: usize) -> Vec<Group> {
    let mut g = Vec::new();
    for _ in 0..n {
        create(&mut g).unwrap();
    }
    g
}

#[test]
fn create_fills_to_the_cap_then_refuses() {
    let mut g = Vec::new();
    for i in 0..MAX_GROUPS {
        assert_eq!(create(&mut g), Some(i as u8));
    }
    assert_eq!(create(&mut g), None);
    assert_eq!(g.len(), MAX_GROUPS);
    assert_eq!(g[0].name, "Group 1");
    assert_eq!(g[7].name, "Group 8");
    assert!(g.iter().all(|g| g.color == g.id % 8));
}

#[test]
fn ids_stay_stable_after_a_remove() {
    let mut g = made(3);
    assert!(remove(&mut g, 1));
    assert_eq!(ids(&g), [0, 2]);
    assert_eq!(find(&g, 2).unwrap().name, "Group 3");
    assert_eq!(create(&mut g), Some(1));
    assert_eq!(ids(&g), [0, 2, 1]);
    assert!(!remove(&mut g, 9));
}

#[test]
fn cycle_walks_none_first_to_last_then_none() {
    let mut g = made(3);
    remove(&mut g, 0);
    create(&mut g);
    let order = ids(&g);
    let mut cur = None;
    let mut seen = Vec::new();
    for _ in 0..order.len() {
        cur = cycle(cur, &g);
        seen.push(cur.unwrap());
    }
    assert_eq!(seen, order);
    assert_eq!(cycle(cur, &g), None);
    assert_eq!(cycle(Some(200), &g), Some(order[0]));
    assert_eq!(cycle(None, &[]), None);
    assert_eq!(cycle(Some(3), &[]), None);
}

#[test]
fn members_and_count_follow_the_filter() {
    let tabs = [Some(1), None, Some(2), Some(1)];
    assert_eq!(members(None, &tabs), [0, 1, 2, 3]);
    assert_eq!(members(Some(1), &tabs), [0, 3]);
    assert!(members(Some(7), &tabs).is_empty());
    assert_eq!((count(1, &tabs), count(2, &tabs), count(5, &tabs)), (2, 1, 0));
}
