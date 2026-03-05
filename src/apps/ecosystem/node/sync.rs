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

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::RwLock;

static SYNC_STATUS: RwLock<SyncStatus> = RwLock::new(SyncStatus::new_const());
static SYNC_START_TIME: AtomicU64 = AtomicU64::new(0);
static BLOCKS_PROCESSED: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStage {
    Idle,
    Headers,
    Bodies,
    Receipts,
    State,
    Finished,
}

#[derive(Debug, Clone)]
pub struct SyncStatus {
    pub stage: SyncStage,
    pub current_block: u64,
    pub highest_block: u64,
    pub starting_block: u64,
    pub pulled_states: u64,
    pub known_states: u64,
    pub syncing: bool,
}

impl SyncStatus {
    pub fn new() -> Self {
        Self {
            stage: SyncStage::Idle,
            current_block: 0,
            highest_block: 0,
            starting_block: 0,
            pulled_states: 0,
            known_states: 0,
            syncing: false,
        }
    }

    pub const fn new_const() -> Self {
        Self {
            stage: SyncStage::Idle,
            current_block: 0,
            highest_block: 0,
            starting_block: 0,
            pulled_states: 0,
            known_states: 0,
            syncing: false,
        }
    }

    pub fn progress(&self) -> f64 {
        if self.highest_block == 0 {
            return 0.0;
        }
        if self.current_block >= self.highest_block {
            return 1.0;
        }

        let total = self.highest_block - self.starting_block;
        if total == 0 {
            return 1.0;
        }

        let synced = self.current_block.saturating_sub(self.starting_block);
        synced as f64 / total as f64
    }

    pub fn progress_percentage(&self) -> f64 {
        self.progress() * 100.0
    }

    pub fn blocks_remaining(&self) -> u64 {
        self.highest_block.saturating_sub(self.current_block)
    }

    pub fn is_synced(&self) -> bool {
        self.current_block >= self.highest_block && self.highest_block > 0
    }

    pub fn stage_name(&self) -> &'static str {
        match self.stage {
            SyncStage::Idle => "Idle",
            SyncStage::Headers => "Downloading headers",
            SyncStage::Bodies => "Downloading bodies",
            SyncStage::Receipts => "Downloading receipts",
            SyncStage::State => "Downloading state",
            SyncStage::Finished => "Finished",
        }
    }

    pub fn state_progress(&self) -> f64 {
        if self.known_states == 0 {
            return 0.0;
        }
        self.pulled_states as f64 / self.known_states as f64
    }
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self::new()
    }
}

pub fn get_sync_status() -> SyncStatus {
    SYNC_STATUS.read().clone()
}

pub fn start_sync(starting_block: u64, highest_block: u64) {
    let mut status = SYNC_STATUS.write();
    status.syncing = true;
    status.starting_block = starting_block;
    status.current_block = starting_block;
    status.highest_block = highest_block;
    status.stage = SyncStage::Headers;

    SYNC_START_TIME.store(crate::time::timestamp_secs(), Ordering::SeqCst);
    BLOCKS_PROCESSED.store(0, Ordering::Relaxed);
}

pub fn stop_sync() {
    let mut status = SYNC_STATUS.write();
    status.syncing = false;
    status.stage = SyncStage::Idle;
}

pub fn update_sync_progress(current_block: u64) {
    let mut status = SYNC_STATUS.write();
    status.current_block = current_block;
    BLOCKS_PROCESSED.fetch_add(1, Ordering::Relaxed);
}

pub fn update_highest_block(highest_block: u64) {
    let mut status = SYNC_STATUS.write();
    if highest_block > status.highest_block {
        status.highest_block = highest_block;
    }
}

pub fn set_sync_stage(stage: SyncStage) {
    let mut status = SYNC_STATUS.write();
    status.stage = stage;

    if stage == SyncStage::Finished {
        status.syncing = false;
    }
}

pub fn update_state_progress(pulled: u64, known: u64) {
    let mut status = SYNC_STATUS.write();
    status.pulled_states = pulled;
    status.known_states = known;
}

pub fn is_syncing() -> bool {
    SYNC_STATUS.read().syncing
}

pub fn is_synced() -> bool {
    SYNC_STATUS.read().is_synced()
}

pub fn get_blocks_per_second() -> f64 {
    let start_time = SYNC_START_TIME.load(Ordering::Relaxed);
    if start_time == 0 {
        return 0.0;
    }

    let elapsed = crate::time::timestamp_secs().saturating_sub(start_time);
    if elapsed == 0 {
        return 0.0;
    }

    let blocks = BLOCKS_PROCESSED.load(Ordering::Relaxed);
    blocks as f64 / elapsed as f64
}

pub fn estimate_time_remaining() -> u64 {
    let status = SYNC_STATUS.read();
    let remaining = status.blocks_remaining();

    let bps = get_blocks_per_second();
    if bps <= 0.0 {
        return u64::MAX;
    }

    (remaining as f64 / bps) as u64
}

pub fn format_eta() -> String {
    let seconds = estimate_time_remaining();

    if seconds == u64::MAX {
        return String::from("Unknown");
    }

    if seconds < 60 {
        return alloc::format!("{}s", seconds);
    }

    let minutes = seconds / 60;
    if minutes < 60 {
        return alloc::format!("{}m {}s", minutes, seconds % 60);
    }

    let hours = minutes / 60;
    if hours < 24 {
        return alloc::format!("{}h {}m", hours, minutes % 60);
    }

    let days = hours / 24;
    alloc::format!("{}d {}h", days, hours % 24)
}

pub fn reset_sync() {
    let mut status = SYNC_STATUS.write();
    *status = SyncStatus::new();
    SYNC_START_TIME.store(0, Ordering::SeqCst);
    BLOCKS_PROCESSED.store(0, Ordering::Relaxed);
}
