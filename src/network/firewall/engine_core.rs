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
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

use super::types::{Action, ConnTrack, FirewallStats, Rule};

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

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    pub fn add_rule(&self, mut rule: Rule) -> u32 {
        rule.id = self.next_rule_id.fetch_add(1, Ordering::SeqCst) as u32;
        let id = rule.id;
        let mut rules = self.rules.write();
        rules.push(rule);
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        id
    }

    pub fn remove_rule(&self, id: u32) -> Result<(), &'static str> {
        let mut rules = self.rules.write();
        if let Some(pos) = rules.iter().position(|r| r.id == id) {
            rules.remove(pos);
            Ok(())
        } else {
            Err("Rule not found")
        }
    }

    pub fn set_rule_enabled(&self, id: u32, enabled: bool) -> Result<(), &'static str> {
        let mut rules = self.rules.write();
        if let Some(rule) = rules.iter_mut().find(|r| r.id == id) {
            rule.enabled = enabled;
            Ok(())
        } else {
            Err("Rule not found")
        }
    }

    pub fn cleanup_expired_connections(&self) {
        let now = crate::time::timestamp_millis();
        let mut ct = self.conntrack.lock();
        let mut expired = Vec::new();

        for (key, conn) in ct.iter() {
            if now.saturating_sub(conn.last_seen_ms) > conn.timeout_ms {
                expired.push(*key);
            }
        }

        for key in expired {
            ct.remove(&key);
            self.stats
                .connections_expired
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn get_stats(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.stats.packets_allowed.load(Ordering::Relaxed),
            self.stats.packets_denied.load(Ordering::Relaxed),
            self.stats.packets_dropped.load(Ordering::Relaxed),
            self.stats.packets_logged.load(Ordering::Relaxed),
            self.stats.connections_tracked.load(Ordering::Relaxed),
        )
    }

    pub fn get_rules(&self) -> Vec<Rule> {
        self.rules.read().clone()
    }

    pub fn connection_count(&self) -> usize {
        self.conntrack.lock().len()
    }
}
