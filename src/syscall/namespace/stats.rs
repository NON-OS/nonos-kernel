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

use core::sync::atomic::{AtomicU64, Ordering};

static TOTAL_NS_CREATED: AtomicU64 = AtomicU64::new(0);
static TOTAL_UNSHARE_CALLS: AtomicU64 = AtomicU64::new(0);
static TOTAL_SETNS_CALLS: AtomicU64 = AtomicU64::new(0);

pub fn record_ns_created() {
    TOTAL_NS_CREATED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_unshare_call() {
    TOTAL_UNSHARE_CALLS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_setns_call() {
    TOTAL_SETNS_CALLS.fetch_add(1, Ordering::Relaxed);
}

pub fn get_total_namespaces() -> u64 {
    TOTAL_NS_CREATED.load(Ordering::Relaxed)
}

pub fn get_total_unshare() -> u64 {
    TOTAL_UNSHARE_CALLS.load(Ordering::Relaxed)
}

pub fn get_total_setns() -> u64 {
    TOTAL_SETNS_CALLS.load(Ordering::Relaxed)
}

pub struct NamespaceStats {
    pub namespaces_created: u64,
    pub unshare_calls: u64,
    pub setns_calls: u64,
}

pub fn get_stats() -> NamespaceStats {
    NamespaceStats {
        namespaces_created: TOTAL_NS_CREATED.load(Ordering::Relaxed),
        unshare_calls: TOTAL_UNSHARE_CALLS.load(Ordering::Relaxed),
        setns_calls: TOTAL_SETNS_CALLS.load(Ordering::Relaxed),
    }
}

pub fn reset_stats() {
    TOTAL_NS_CREATED.store(0, Ordering::Relaxed);
    TOTAL_UNSHARE_CALLS.store(0, Ordering::Relaxed);
    TOTAL_SETNS_CALLS.store(0, Ordering::Relaxed);
}
