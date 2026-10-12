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

//! A tab out of view steps leaving streams free at each proxy for the tab
//! in view: it takes one only while more than `SPARE` are free.

use crate::browser::net::mixnet::streams::{lowest_free, lowest_free_leaving, SPARE, STREAMS};

#[test]
fn with_nothing_to_leave_every_stream_is_taken() {
    let used: Vec<u32> = (1..STREAMS).collect();
    assert_eq!(lowest_free_leaving(&used, 0), lowest_free(&used));
    assert_eq!(lowest_free_leaving(&used, 0), Some(STREAMS));
}

#[test]
fn a_tab_out_of_view_never_takes_the_spare() {
    let mut used = Vec::new();
    while let Some(s) = lowest_free_leaving(&used, SPARE) {
        used.push(s);
    }
    assert_eq!(used.len() as u32, STREAMS - SPARE);
    assert_eq!(used, (1..=STREAMS - SPARE).collect::<Vec<_>>());
    assert!(lowest_free(&used).is_some(), "the tab in view still finds one");
}

#[test]
fn freed_streams_below_the_spare_are_taken_lowest_first() {
    let used = [2, 5, 7];
    assert_eq!(lowest_free_leaving(&used, SPARE), Some(1));
    assert_eq!(lowest_free_leaving(&[1, 2, 3, 5], SPARE), None);
}
