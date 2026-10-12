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

use alloc::string::String;
use alloc::vec::Vec;

use super::route::keeps;
use super::types::Visit;

pub const MAX_VISITS: usize = 512;

/// Appends `v`, or refreshes the newest entry when it is the same URL, then
/// drops the oldest entries past `MAX_VISITS`.
pub fn record(visits: &mut Vec<Visit>, v: Visit) {
    match visits.last_mut() {
        Some(last) if last.url == v.url => {
            last.at_ms = v.at_ms;
            last.title = v.title;
            last.route = v.route;
        }
        _ => visits.push(v),
    }
    let over = visits.len().saturating_sub(MAX_VISITS);
    visits.drain(..over);
}

/// Indices of the visits History filter pill `pill` lists, newest first.
pub fn filter(visits: &[Visit], pill: u8) -> Vec<usize> {
    (0..visits.len()).rev().filter(|&i| keeps(pill, visits[i].route)).collect()
}

/// The host part of `url`, or empty when it does not parse.
pub fn host_of(url: &str) -> String {
    crate::browser::url::parse(url).map(|u| u.host).unwrap_or_default()
}

/// The `n` hosts visited most, with their visit counts. Ties go to the host
/// visited most recently. Visits without a host are not counted.
pub fn top_sites(visits: &[Visit], n: usize) -> Vec<(String, u32)> {
    let mut tally: Vec<(String, u32, usize)> = Vec::new();
    for (i, v) in visits.iter().enumerate().filter(|(_, v)| !v.host.is_empty()) {
        match tally.iter_mut().find(|t| t.0 == v.host) {
            Some(t) => {
                t.1 += 1;
                t.2 = i;
            }
            None => tally.push((v.host.clone(), 1, i)),
        }
    }
    tally.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)));
    tally.into_iter().take(n).map(|(host, count, _)| (host, count)).collect()
}
