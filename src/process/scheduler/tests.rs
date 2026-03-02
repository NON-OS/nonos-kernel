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
fn rr_basic_rotation() {
    let rq = RunQueue::new(3);
    rq.push(1);
    rq.push(2);
    rq.push(3);

    // First pick
    let p = rq.pick_next().unwrap();
    assert_eq!(p, 1);

    // 3 ticks -> rotate to 2
    assert_eq!(rq.on_timer_tick(), Some(1));
    assert_eq!(rq.on_timer_tick(), Some(1));
    let p = rq.on_timer_tick().unwrap(); // slice expires
    assert_eq!(p, 2);

    // Next rotation -> 3
    assert_eq!(rq.on_timer_tick(), Some(2));
    assert_eq!(rq.on_timer_tick(), Some(2));
    let p = rq.on_timer_tick().unwrap();
    assert_eq!(p, 3);
}

#[test]
fn no_duplicates() {
    let rq = RunQueue::new(2);
    rq.push(10);
    rq.push(10);
    assert_eq!(rq.len(), 1);
    let _ = rq.pick_next();
    // Already current, push ignored
    rq.push(10);
    assert!(rq.is_empty());
}

#[test]
fn yield_moves_current_to_back() {
    let rq = RunQueue::new(5);
    rq.push(7);
    rq.push(8);
    rq.push(9);
    assert_eq!(rq.pick_next(), Some(7));
    assert_eq!(rq.yield_current(), Some(8));
    // 7 should now be queued after 9
    assert_eq!(rq.yield_current(), Some(9));
    assert_eq!(rq.yield_current(), Some(7));
}

#[test]
fn remove_from_queue() {
    let rq = RunQueue::new(4);
    rq.push(1);
    rq.push(2);
    rq.push(3);
    assert!(rq.remove(2));
    assert_eq!(rq.len(), 2);
    assert!(!rq.remove(2));
}

#[test]
fn clear_current_and_pick() {
    let rq = RunQueue::new(1);
    rq.push(4);
    rq.push(5);
    assert_eq!(rq.pick_next(), Some(4));
    assert_eq!(rq.clear_current(), Some(4));
    // Next should be 5
    assert_eq!(rq.pick_next(), Some(5));
}
