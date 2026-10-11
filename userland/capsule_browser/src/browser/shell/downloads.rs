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

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::dl_name::name_of;
use super::types::{DlState, Download, Downloaded};

pub const MAX_DOWNLOADS: usize = 64;
pub const MAX_SAVE: usize = 32 * 1024 * 1024;

/// A tab's mailbox entry for `body`, which is kept only up to `MAX_SAVE`.
pub fn received(url: String, body: Vec<u8>) -> Downloaded {
    let bytes = body.len() as u64;
    Downloaded { url, bytes, body: (body.len() <= MAX_SAVE).then_some(body) }
}

/// Records a download, dropping the oldest past `MAX_DOWNLOADS`.
pub fn push(list: &mut Vec<Download>, url: &str, bytes: u64, at_ms: i64, state: DlState) {
    list.push(Download { name: name_of(url), url: String::from(url), bytes, at_ms, state });
    let over = list.len().saturating_sub(MAX_DOWNLOADS);
    list.drain(..over);
}

/// Settles the `Saving` record of `url` started at `at_ms`: `Saved` under the
/// name it was written as, or `Failed` with the reason.
pub fn push_saved(list: &mut [Download], url: &str, at_ms: i64, saved: Result<String, &str>) {
    let Some(d) = list.iter_mut().find(|d| d.url == url && d.at_ms == at_ms) else {
        return;
    };
    match saved {
        Ok(name) => {
            d.state = DlState::Saved;
            d.name = name;
        }
        Err(why) => d.state = DlState::Failed(String::from(why)),
    }
}

pub fn push_failed(list: &mut Vec<Download>, url: &str, bytes: u64, at_ms: i64, why: &str) {
    push(list, url, bytes, at_ms, DlState::Failed(String::from(why)));
}

/// `[all, saved, failed]`; a download still saving counts only under all.
pub fn counts(list: &[Download]) -> [usize; 3] {
    let failed = list.iter().filter(|d| matches!(d.state, DlState::Failed(_))).count();
    let saved = list.iter().filter(|d| d.state == DlState::Saved).count();
    [list.len(), saved, failed]
}

/// Indices of the downloads filter pill `pill` (All, Saved, Failed) lists,
/// newest first.
pub fn filter(list: &[Download], pill: u8) -> Vec<usize> {
    let keep = |d: &Download| match pill {
        1 => d.state == DlState::Saved,
        2 => matches!(d.state, DlState::Failed(_)),
        _ => true,
    };
    (0..list.len()).rev().filter(|&i| keep(&list[i])).collect()
}

/// A size for people: `17 B`, `512 KB`, `3.8 MB`, `1.2 GB` (tenths cut).
pub fn human_bytes(n: u64) -> String {
    const K: u64 = 1024;
    match n {
        0..K => format!("{} B", n),
        K..0x10_0000 => format!("{} KB", n / K),
        0x10_0000..0x4000_0000 => format!("{}.{} MB", n / (K * K), n * 10 / (K * K) % 10),
        _ => format!("{}.{} GB", n / (K * K * K), n / (K * K) * 10 / K % 10),
    }
}
