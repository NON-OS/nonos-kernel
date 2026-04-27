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

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use spin::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pending,
    Downloading,
    Verifying,
    Loading,
    Cached,
    Complete,
    Failed,
}

struct ProgressEntry {
    status: Status,
    bytes_downloaded: u64,
    total_bytes: u64,
    started_at: u64,
}
static PROGRESS: RwLock<Option<BTreeMap<String, ProgressEntry>>> = RwLock::new(None);

pub fn init() {
    *PROGRESS.write() = Some(BTreeMap::new());
}

pub fn set_status(cid: &str, status: Status) {
    if let Some(p) = PROGRESS.write().as_mut() {
        let entry = p.entry(String::from(cid)).or_insert_with(|| ProgressEntry {
            status: Status::Pending,
            bytes_downloaded: 0,
            total_bytes: 0,
            started_at: crate::time::unix_timestamp(),
        });
        entry.status = status;
    }
}

pub fn set_progress(cid: &str, downloaded: u64, total: u64) {
    if let Some(p) = PROGRESS.write().as_mut() {
        if let Some(entry) = p.get_mut(cid) {
            entry.bytes_downloaded = downloaded;
            entry.total_bytes = total;
        }
    }
}

pub fn get_status(cid: &str) -> Status {
    PROGRESS.read().as_ref().and_then(|p| p.get(cid).map(|e| e.status)).unwrap_or(Status::Pending)
}

pub fn get_progress(cid: &str) -> (u64, u64) {
    PROGRESS
        .read()
        .as_ref()
        .and_then(|p| p.get(cid).map(|e| (e.bytes_downloaded, e.total_bytes)))
        .unwrap_or((0, 0))
}

pub fn clear(cid: &str) {
    if let Some(p) = PROGRESS.write().as_mut() {
        p.remove(cid);
    }
}

pub fn clear_completed() {
    if let Some(p) = PROGRESS.write().as_mut() {
        p.retain(|_, e| e.status != Status::Complete && e.status != Status::Failed);
    }
}

pub fn active_count() -> usize {
    PROGRESS
        .read()
        .as_ref()
        .map(|p| p.values().filter(|e| e.status == Status::Downloading).count())
        .unwrap_or(0)
}

pub fn get_elapsed_secs(cid: &str) -> u64 {
    let now = crate::time::unix_timestamp();
    PROGRESS
        .read()
        .as_ref()
        .and_then(|p| p.get(cid).map(|e| now.saturating_sub(e.started_at)))
        .unwrap_or(0)
}

pub fn get_download_speed(cid: &str) -> u64 {
    let elapsed = get_elapsed_secs(cid);
    if elapsed == 0 {
        return 0;
    }
    let (downloaded, _) = get_progress(cid);
    downloaded / elapsed
}
