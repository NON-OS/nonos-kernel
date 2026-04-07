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
use spin::RwLock;

#[derive(Debug, Clone, Copy)]
pub struct IdMapping { pub inside_id: u32, pub outside_id: u32, pub count: u32 }

#[derive(Debug, Clone, Default)]
pub struct UserNamespace {
    pub uid_map: Vec<IdMapping>,
    pub gid_map: Vec<IdMapping>,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub parent_ns: u64,
}

static USER_NS_DATA: RwLock<BTreeMap<u64, UserNamespace>> = RwLock::new(BTreeMap::new());

pub fn create_user_ns(ns_id: u64, owner_uid: u32, owner_gid: u32, parent_ns: u64) {
    let mut data = USER_NS_DATA.write();
    data.insert(ns_id, UserNamespace {
        uid_map: Vec::new(), gid_map: Vec::new(), owner_uid, owner_gid, parent_ns
    });
}

pub fn set_uid_map(ns_id: u64, mappings: Vec<IdMapping>) -> Result<(), i32> {
    let mut data = USER_NS_DATA.write();
    let ns = data.get_mut(&ns_id).ok_or(-1)?;
    if !ns.uid_map.is_empty() { return Err(-1); }
    if !validate_mappings(&mappings) { return Err(-22); }
    ns.uid_map = mappings;
    Ok(())
}

pub fn set_gid_map(ns_id: u64, mappings: Vec<IdMapping>) -> Result<(), i32> {
    let mut data = USER_NS_DATA.write();
    let ns = data.get_mut(&ns_id).ok_or(-1)?;
    if !ns.gid_map.is_empty() { return Err(-1); }
    if !validate_mappings(&mappings) { return Err(-22); }
    ns.gid_map = mappings;
    Ok(())
}

fn validate_mappings(mappings: &[IdMapping]) -> bool {
    if mappings.is_empty() || mappings.len() > 340 { return false; }
    for i in 0..mappings.len() {
        if mappings[i].count == 0 { return false; }
        for j in (i + 1)..mappings.len() {
            let a = &mappings[i]; let b = &mappings[j];
            if ranges_overlap(a.inside_id, a.count, b.inside_id, b.count) { return false; }
            if ranges_overlap(a.outside_id, a.count, b.outside_id, b.count) { return false; }
        }
    }
    true
}

fn ranges_overlap(s1: u32, c1: u32, s2: u32, c2: u32) -> bool {
    let e1 = s1.saturating_add(c1); let e2 = s2.saturating_add(c2);
    !(e1 <= s2 || e2 <= s1)
}

pub fn map_uid_to_ns(ns_id: u64, external_uid: u32) -> Option<u32> {
    let data = USER_NS_DATA.read();
    let ns = data.get(&ns_id)?;
    for m in &ns.uid_map {
        if external_uid >= m.outside_id && external_uid < m.outside_id.saturating_add(m.count) {
            return Some(m.inside_id + (external_uid - m.outside_id));
        }
    }
    None
}

pub fn map_uid_from_ns(ns_id: u64, internal_uid: u32) -> Option<u32> {
    let data = USER_NS_DATA.read();
    let ns = data.get(&ns_id)?;
    for m in &ns.uid_map {
        if internal_uid >= m.inside_id && internal_uid < m.inside_id.saturating_add(m.count) {
            return Some(m.outside_id + (internal_uid - m.inside_id));
        }
    }
    None
}

pub fn get_user_ns(ns_id: u64) -> Option<UserNamespace> { USER_NS_DATA.read().get(&ns_id).cloned() }
pub fn delete_user_ns(ns_id: u64) { USER_NS_DATA.write().remove(&ns_id); }
