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

use spin::Mutex;

pub(super) struct Interface {
    pub name: [u8; 16],
    pub mac: [u8; 6],
    pub ipv4: u32,
    pub netmask: u32,
    pub gateway: u32,
    pub up: bool,
    pub dhcp: bool,
}

static INTERFACES: Mutex<[Option<Interface>; 8]> = Mutex::new([const { None }; 8]);

pub(super) fn register_interface(name: &[u8], mac: &[u8; 6]) -> Option<u8> {
    let mut ifaces = INTERFACES.lock();
    for (i, slot) in ifaces.iter_mut().enumerate() {
        if slot.is_none() {
            let mut iface_name = [0u8; 16];
            let len = core::cmp::min(name.len(), 16);
            iface_name[..len].copy_from_slice(&name[..len]);
            *slot = Some(Interface {
                name: iface_name,
                mac: *mac,
                ipv4: 0,
                netmask: 0,
                gateway: 0,
                up: false,
                dhcp: true,
            });
            return Some(i as u8);
        }
    }
    None
}

pub(super) fn set_ipv4(index: u8, ipv4: u32, netmask: u32, gateway: u32) -> bool {
    let mut ifaces = INTERFACES.lock();
    if let Some(Some(iface)) = ifaces.get_mut(index as usize) {
        iface.ipv4 = ipv4;
        iface.netmask = netmask;
        iface.gateway = gateway;
        return true;
    }
    false
}

pub(super) fn set_up(index: u8, up: bool) -> bool {
    let mut ifaces = INTERFACES.lock();
    if let Some(Some(iface)) = ifaces.get_mut(index as usize) {
        iface.up = up;
        return true;
    }
    false
}

pub(super) fn get_interface(index: u8) -> Option<Interface> {
    let ifaces = INTERFACES.lock();
    ifaces.get(index as usize)?.as_ref().map(|i| Interface {
        name: i.name,
        mac: i.mac,
        ipv4: i.ipv4,
        netmask: i.netmask,
        gateway: i.gateway,
        up: i.up,
        dhcp: i.dhcp,
    })
}

pub(super) fn interface_count() -> u8 {
    INTERFACES.lock().iter().filter(|i| i.is_some()).count() as u8
}
