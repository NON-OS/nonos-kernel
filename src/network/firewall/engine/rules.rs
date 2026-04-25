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

use super::firewall::Firewall;
use crate::network::firewall::types::Rule;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

impl Firewall {
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

    pub fn get_rules(&self) -> Vec<Rule> {
        self.rules.read().clone()
    }
}
