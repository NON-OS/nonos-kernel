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

use crate::network::firewall::types::{Action, ConnTrack, FirewallStats, Rule};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64};
use spin::{Mutex, RwLock};

pub struct Firewall {
    pub(super) enabled: AtomicBool,
    pub(super) default_inbound: Action,
    pub(super) default_outbound: Action,
    pub(super) rules: RwLock<Vec<Rule>>,
    pub(super) conntrack: Mutex<BTreeMap<u64, ConnTrack>>,
    pub(super) stats: FirewallStats,
    pub(super) next_rule_id: AtomicU64,
}

impl Firewall {
    pub const fn new() -> Self {
        Self {
            enabled: AtomicBool::new(true),
            default_inbound: Action::Deny,
            default_outbound: Action::Allow,
            rules: RwLock::new(Vec::new()),
            conntrack: Mutex::new(BTreeMap::new()),
            stats: FirewallStats {
                packets_allowed: AtomicU64::new(0),
                packets_denied: AtomicU64::new(0),
                packets_dropped: AtomicU64::new(0),
                packets_logged: AtomicU64::new(0),
                packets_rate_limited: AtomicU64::new(0),
                connections_tracked: AtomicU64::new(0),
                connections_expired: AtomicU64::new(0),
            },
            next_rule_id: AtomicU64::new(1),
        }
    }
}
