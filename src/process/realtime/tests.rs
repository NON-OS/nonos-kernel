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

use super::*;

#[test]
fn set_get_clear() {
    let pid = 42;
    assert!(get_deadline(pid).is_none());
    set_deadline(pid, Deadline { tsc_deadline: 1_000_000, slack_ns: 0 }).unwrap();
    let d = get_deadline(pid).unwrap();
    assert_eq!(d.tsc_deadline, 1_000_000);
    assert!(clear_deadline(pid));
    assert!(get_deadline(pid).is_none());
    assert!(!clear_deadline(pid));
}

#[test]
fn list_and_check_with_freq() {
    set_deadline(1, Deadline { tsc_deadline: 1_000_000, slack_ns: 0 }).unwrap();
    set_deadline(2, Deadline { tsc_deadline: 9_000_000, slack_ns: 0 }).unwrap();

    let missed = check_and_mark_deadlines(5_000_000, 1_000_000_000);
    assert_eq!(missed, alloc::vec![1]);
    assert_eq!(stats_deadline_misses(), 1);

    let missed2 = check_and_mark_deadlines(10_000_000, 1_000_000_000);
    assert!(missed2.contains(&1) && missed2.contains(&2));
    assert_eq!(stats_deadline_misses(), 1 + missed2.len() as u64);
}

#[test]
fn slack_conversion() {
    set_deadline(10, Deadline { tsc_deadline: 1_000_000, slack_ns: 100 }).unwrap();
    let m1 = check_and_mark_deadlines(1_000_050, 1_000_000_000);
    assert!(m1.is_empty());
    let m2 = check_and_mark_deadlines(1_000_200, 1_000_000_000);
    assert_eq!(m2, alloc::vec![10]);
}

#[test]
fn invalid_inputs() {
    assert!(set_deadline(0, Deadline { tsc_deadline: 1, slack_ns: 0 }).is_err());
    assert!(set_deadline(1, Deadline { tsc_deadline: 0, slack_ns: 0 }).is_err());
}
