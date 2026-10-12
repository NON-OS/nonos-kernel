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

//! Every tab's image store charges one count for the process: a store
//! cannot take it past the process budget, and a store that goes, resets
//! or is put away out of view gives its rasters back.

use super::store_tests::bmp;
use crate::browser::image::resident::{held, PROCESS_BUDGET};
use crate::browser::image::{ingest, note_size, Store};

const MIB4: usize = 4 * 1024 * 1024;

fn fill(s: &mut Store, prefix: &str, n: usize) {
    for i in 0..n {
        let url = format!("{prefix}{i}");
        note_size(s, &url, 1024, 1024);
        ingest(s, &url, &bmp(1024, 1024, [i as u8, 2, 3]));
        assert!(s.ready(&url).is_some(), "{url} must fit");
    }
}

#[test]
fn every_store_charges_the_process_count() {
    let (mut a, mut b) = (Store::new(), Store::new());
    fill(&mut a, "a", 3);
    fill(&mut b, "b", 2);
    assert_eq!(held(), 5 * MIB4);
}

#[test]
fn no_store_takes_the_process_past_its_budget() {
    let mut full: Vec<Store> = (0..PROCESS_BUDGET / (4 * MIB4)).map(|_| Store::new()).collect();
    for (i, s) in full.iter_mut().enumerate() {
        fill(s, &format!("s{i}-"), 4);
    }
    assert_eq!(held(), PROCESS_BUDGET);
    let mut late = Store::new();
    note_size(&mut late, "late", 1024, 1024);
    ingest(&mut late, "late", &bmp(1024, 1024, [9, 9, 9]));
    assert!(late.ready("late").is_none(), "nothing of its own to evict: no room");
    assert_eq!(held(), PROCESS_BUDGET);
    drop(full.pop());
    fill(&mut late, "again", 1);
    assert_eq!(held(), PROCESS_BUDGET - 3 * MIB4);
}

#[test]
fn reset_drop_and_put_away_give_the_bytes_back() {
    let mut a = Store::new();
    fill(&mut a, "a", 2);
    a.reset();
    assert_eq!(held(), 0);
    fill(&mut a, "a", 2);
    a.put_away(&[]);
    assert_eq!(held(), 0);
    assert!(a.ready("a0").is_none() && a.contains("a0"), "evicted, not forgotten");
    assert_eq!(a.natural("a0"), Some((1024, 1024)), "its layout size stays");
    fill(&mut a, "b", 1);
    drop(a);
    assert_eq!(held(), 0);
}
