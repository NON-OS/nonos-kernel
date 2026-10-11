// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The start page greeting, from the UTC hour of the wall clock.

use crate::browser::shell::clock::hour_greeting;

const MIN: i64 = 60_000;
const HOUR: i64 = 60 * MIN;
const DAY: i64 = 24 * HOUR;

fn at(h: i64, m: i64) -> i64 {
    19_000 * DAY + h * HOUR + m * MIN
}

#[test]
fn greeting_boundaries() {
    assert_eq!(hour_greeting(at(4, 59)), "Good evening");
    assert_eq!(hour_greeting(at(5, 0)), "Good morning");
    assert_eq!(hour_greeting(at(11, 59)), "Good morning");
    assert_eq!(hour_greeting(at(12, 0)), "Good afternoon");
    assert_eq!(hour_greeting(at(17, 59)), "Good afternoon");
    assert_eq!(hour_greeting(at(18, 0)), "Good evening");
    assert_eq!(hour_greeting(at(23, 59)), "Good evening");
    assert_eq!(hour_greeting(at(0, 0)), "Good evening");
}

#[test]
fn an_unset_or_negative_clock_says_hello() {
    assert_eq!(hour_greeting(0), "Hello");
    assert_eq!(hour_greeting(-1), "Hello");
    assert_eq!(hour_greeting(i64::MIN), "Hello");
}
