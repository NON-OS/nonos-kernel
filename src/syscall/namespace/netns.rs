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
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use spin::RwLock;

#[derive(Debug, Clone)]
pub struct NetNamespace {
    pub loopback_up: bool,
    pub interfaces: BTreeSet<u32>,
    pub routes: Vec<NetRoute>,
    pub firewall_rules: Vec<u32>,
    pub veth_pairs: Vec<(u64, u32)>,
}

#[derive(Debug, Clone)]
pub struct NetRoute { pub dest: [u8; 4], pub mask: u8, pub gateway: [u8; 4], pub iface: u32 }

impl Default for NetNamespace {
    fn default() -> Self {
        Self { loopback_up: true, interfaces: BTreeSet::new(), routes: Vec::new(),
            firewall_rules: Vec::new(), veth_pairs: Vec::new() }
    }
}

static NET_NS_DATA: RwLock<BTreeMap<u64, NetNamespace>> = RwLock::new(BTreeMap::new());

pub fn create_net_ns(ns_id: u64) {
    let mut data = NET_NS_DATA.write();
    data.insert(ns_id, NetNamespace::default());
}

pub fn add_interface(ns_id: u64, iface_id: u32) -> Result<(), i32> {
    let mut data = NET_NS_DATA.write();
    let ns = data.get_mut(&ns_id).ok_or(-1)?;
    ns.interfaces.insert(iface_id);
    Ok(())
}

pub fn remove_interface(ns_id: u64, iface_id: u32) -> Result<(), i32> {
    let mut data = NET_NS_DATA.write();
    let ns = data.get_mut(&ns_id).ok_or(-1)?;
    ns.interfaces.remove(&iface_id);
    Ok(())
}

pub fn add_route(ns_id: u64, route: NetRoute) -> Result<(), i32> {
    let mut data = NET_NS_DATA.write();
    let ns = data.get_mut(&ns_id).ok_or(-1)?;
    ns.routes.push(route);
    Ok(())
}

pub fn create_veth_pair(ns_id_a: u64, ns_id_b: u64) -> Result<(u32, u32), i32> {
    let veth_a = crate::crypto::secure_random_u32() & 0xFFFF;
    let veth_b = veth_a ^ 0x8000;
    let mut data = NET_NS_DATA.write();
    if let Some(ns_a) = data.get_mut(&ns_id_a) {
        ns_a.interfaces.insert(veth_a);
        ns_a.veth_pairs.push((ns_id_b, veth_b));
    }
    if let Some(ns_b) = data.get_mut(&ns_id_b) {
        ns_b.interfaces.insert(veth_b);
        ns_b.veth_pairs.push((ns_id_a, veth_a));
    }
    Ok((veth_a, veth_b))
}

pub fn can_access_interface(ns_id: u64, iface_id: u32) -> bool {
    let data = NET_NS_DATA.read();
    data.get(&ns_id).map(|ns| ns.interfaces.contains(&iface_id)).unwrap_or(false)
}

pub fn get_net_ns(ns_id: u64) -> Option<NetNamespace> { NET_NS_DATA.read().get(&ns_id).cloned() }
pub fn delete_net_ns(ns_id: u64) { NET_NS_DATA.write().remove(&ns_id); }
pub fn list_interfaces(ns_id: u64) -> Vec<u32> {
    NET_NS_DATA.read().get(&ns_id).map(|ns| ns.interfaces.iter().copied().collect()).unwrap_or_default()
}
