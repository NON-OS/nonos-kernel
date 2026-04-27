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

use crate::network::nym::types::{NymAddress, NYM_COVER_INTERVAL_MS};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

static COVER_RUNNING: AtomicBool = AtomicBool::new(false);
static COVER_PACKETS_SENT: AtomicU64 = AtomicU64::new(0);
static SELF_ADDRESS: Mutex<Option<NymAddress>> = Mutex::new(None);

pub struct CoverScheduler {
    interval_ms: u64,
    running: bool,
}

pub fn start_cover_traffic(self_address: NymAddress) {
    *SELF_ADDRESS.lock() = Some(self_address);
    COVER_RUNNING.store(true, Ordering::SeqCst);
}

pub fn stop_cover_traffic() {
    COVER_RUNNING.store(false, Ordering::SeqCst);
}

pub fn is_cover_traffic_running() -> bool {
    COVER_RUNNING.load(Ordering::SeqCst)
}

pub fn cover_packets_sent() -> u64 {
    COVER_PACKETS_SENT.load(Ordering::Relaxed)
}

pub fn tick_cover_traffic(self_addr: &NymAddress) {
    if !COVER_RUNNING.load(Ordering::SeqCst) {
        return;
    }
    if let Ok(_packet) = super::generator::generate_cover_packet(self_addr) {
        COVER_PACKETS_SENT.fetch_add(1, Ordering::Relaxed);
    }
}

impl CoverScheduler {
    pub fn new(interval_ms: u64) -> Self {
        Self { interval_ms, running: false }
    }

    pub fn start(&mut self, self_address: NymAddress) {
        self.running = true;
        start_cover_traffic(self_address);
    }

    pub fn stop(&mut self) {
        self.running = false;
        stop_cover_traffic();
    }

    pub fn tick(&self) {
        if !COVER_RUNNING.load(Ordering::SeqCst) {
            return;
        }
        let addr = SELF_ADDRESS.lock();
        if let Some(self_addr) = addr.as_ref() {
            if let Ok(_packet) = super::generator::generate_cover_packet(self_addr) {
                COVER_PACKETS_SENT.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn interval_ms(&self) -> u64 {
        self.interval_ms
    }
}

impl Default for CoverScheduler {
    fn default() -> Self {
        Self::new(NYM_COVER_INTERVAL_MS)
    }
}
