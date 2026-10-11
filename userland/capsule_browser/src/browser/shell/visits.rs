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

use super::types::Visit;

pub const MAX_VISITS: usize = 512;

/// Appends a visit to `url`, unless the newest entry already is one, then
/// drops the oldest entries past `MAX_VISITS`.
pub fn record(visits: &mut Vec<Visit>, url: &str) {
    if visits.last().is_some_and(|v| v.url == url) {
        return;
    }
    visits.push(Visit { url: String::from(url), host: host_of(url) });
    let over = visits.len().saturating_sub(MAX_VISITS);
    visits.drain(..over);
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
