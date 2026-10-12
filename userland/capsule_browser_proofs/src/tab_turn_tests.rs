// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The turn the busy tabs out of view take to step, one a tick.

use crate::browser::ui::tab_turn::next_busy;

#[test]
fn next_busy_wraps_and_skips_idle_tabs() {
    assert_eq!(next_busy(0, &[false, true, false, true]), Some(1));
    assert_eq!(next_busy(2, &[false, true, false, true]), Some(3));
    assert_eq!(next_busy(0, &[false, false, true, false]), Some(2));
    assert_eq!(next_busy(3, &[true, false, false, false]), Some(0));
    assert_eq!(next_busy(1, &[false, true]), Some(1));
}

#[test]
fn next_busy_is_none_when_all_idle_or_empty() {
    assert_eq!(next_busy(0, &[false; 6]), None);
    assert_eq!(next_busy(5, &[]), None);
}

#[test]
fn next_busy_round_robin_visits_every_busy_tab() {
    let busy = [true, false, true, true, false, true];
    let mut cursor = 0;
    let mut seen = Vec::new();
    for _ in 0..4 {
        let i = next_busy(cursor, &busy).unwrap();
        seen.push(i);
        cursor = i + 1;
    }
    assert_eq!(seen, [0, 2, 3, 5]);
    assert_eq!(next_busy(cursor, &busy), Some(0));
}
