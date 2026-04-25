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

use super::constants::*;
use super::control::{
    clear_connection_change, get_hub_descriptor, get_port_status, power_on_port, reset_port,
};
use super::types::{HubState, PortState};
use crate::drivers::usb::error::UsbError;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};
use spin::Mutex;

static HUBS: Mutex<Vec<HubState>> = Mutex::new(Vec::new());
static NEXT_ADDRESS: AtomicU8 = AtomicU8::new(2);

pub fn register_hub(slot_id: u8) -> Result<usize, UsbError> {
    let desc = get_hub_descriptor(slot_id)?;
    let state = HubState::new(slot_id, desc.num_ports, desc.power_on_delay * 2, false, 1);
    let mut hubs = HUBS.lock();
    let idx = hubs.len();
    hubs.push(state);
    Ok(idx)
}

pub fn init_hub_ports(slot_id: u8, hub_idx: usize) -> Result<(), UsbError> {
    let num_ports = { HUBS.lock().get(hub_idx).map(|h| h.num_ports).unwrap_or(0) };
    for port in 1..=num_ports {
        power_on_port(slot_id, port)?;
    }
    let delay = {
        HUBS.lock()
            .get(hub_idx)
            .map(|h| h.power_on_delay_ms as u64)
            .unwrap_or(HUB_POWER_ON_DELAY_MS as u64)
    };
    crate::time::delay_ms(delay);
    for port in 1..=num_ports {
        let status = get_port_status(slot_id, port)?;
        let state = if status.connected() { PortState::Connected } else { PortState::Powered };
        if let Some(hub) = HUBS.lock().get_mut(hub_idx) {
            hub.port_states[port as usize - 1] = state;
        }
    }
    Ok(())
}

pub fn poll_hub(slot_id: u8, hub_idx: usize) -> Result<Vec<u8>, UsbError> {
    let num_ports = { HUBS.lock().get(hub_idx).map(|h| h.num_ports).unwrap_or(0) };
    let mut changed = Vec::new();
    for port in 1..=num_ports {
        let status = get_port_status(slot_id, port)?;
        if status.connection_changed() {
            clear_connection_change(slot_id, port)?;
            changed.push(port);
            let state =
                if status.connected() { PortState::Connected } else { PortState::Disconnected };
            if let Some(hub) = HUBS.lock().get_mut(hub_idx) {
                hub.port_states[port as usize - 1] = state;
            }
        }
    }
    Ok(changed)
}

pub fn enumerate_port(slot_id: u8, hub_idx: usize, port: u8) -> Result<u8, UsbError> {
    reset_port(slot_id, port)?;
    crate::time::delay_ms(HUB_DEBOUNCE_MS as u64);
    let status = get_port_status(slot_id, port)?;
    if !status.enabled() {
        return Err(UsbError::SlotNotEnabled);
    }
    let new_addr = NEXT_ADDRESS.fetch_add(1, Ordering::SeqCst);
    if let Some(hub) = HUBS.lock().get_mut(hub_idx) {
        hub.port_states[port as usize - 1] = PortState::Enabled;
        hub.port_devices[port as usize - 1] = Some(new_addr);
    }
    Ok(new_addr)
}

pub fn hub_count() -> usize {
    HUBS.lock().len()
}
pub fn get_hub(idx: usize) -> Option<HubState> {
    HUBS.lock().get(idx).cloned()
}
