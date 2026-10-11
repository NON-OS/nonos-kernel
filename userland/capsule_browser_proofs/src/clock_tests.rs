// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(test)]
//! The start page greeting, from the UTC hour of the wall clock, and the
//! times the History and Bookmarks pages give their rows.

use crate::browser::shell::clock::{ago, hhmm, hour_greeting};

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

#[test]
fn hhmm_formats_the_utc_time() {
    assert_eq!(hhmm(0), "00:00");
    assert_eq!(hhmm(at(9, 5)), "09:05");
    assert_eq!(hhmm(at(23, 59)), "23:59");
    assert_eq!(hhmm(at(23, 59) + MIN), "00:00");
    assert_eq!(hhmm(-5 * HOUR), "00:00");
    let far = hhmm(i64::MAX);
    assert!(far.len() == 5 && far.as_bytes()[2] == b':', "{far}");
}

#[test]
fn ago_steps_through_minutes_hours_days() {
    let now = at(12, 0);
    assert_eq!(ago(now, now), "just now");
    assert_eq!(ago(now, now - 59_999), "just now");
    assert_eq!(ago(now, now + HOUR), "just now");
    assert_eq!(ago(now, now - MIN), "1 min ago");
    assert_eq!(ago(now, now - 59 * MIN - 59_000), "59 min ago");
    assert_eq!(ago(now, now - HOUR), "1 h ago");
    assert_eq!(ago(now, now - DAY + 1000), "23 h ago");
    assert_eq!(ago(now, now - DAY), "1 d ago");
    assert_eq!(ago(now, now - 40 * DAY), "40 d ago");
    assert!(ago(i64::MAX, i64::MIN).ends_with(" d ago"));
    assert_eq!(ago(i64::MIN, i64::MAX), "just now");
}
