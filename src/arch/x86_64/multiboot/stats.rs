// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::sync::atomic::{AtomicU64, Ordering};

pub struct MultibootStats {
    pub memory_entries_parsed: AtomicU64,
    pub modules_parsed: AtomicU64,
    pub tags_processed: AtomicU64,
    pub unknown_tags: AtomicU64,
    pub parse_errors: AtomicU64,
    pub total_available_memory: AtomicU64,
    pub total_reserved_memory: AtomicU64,
}

impl MultibootStats {
    pub const fn new() -> Self {
        Self {
            memory_entries_parsed: AtomicU64::new(0),
            modules_parsed: AtomicU64::new(0),
            tags_processed: AtomicU64::new(0),
            unknown_tags: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            total_available_memory: AtomicU64::new(0),
            total_reserved_memory: AtomicU64::new(0),
        }
    }

    pub fn reset(&self) {
        self.memory_entries_parsed.store(0, Ordering::SeqCst);
        self.modules_parsed.store(0, Ordering::SeqCst);
        self.tags_processed.store(0, Ordering::SeqCst);
        self.unknown_tags.store(0, Ordering::SeqCst);
        self.parse_errors.store(0, Ordering::SeqCst);
        self.total_available_memory.store(0, Ordering::SeqCst);
        self.total_reserved_memory.store(0, Ordering::SeqCst);
    }
}
