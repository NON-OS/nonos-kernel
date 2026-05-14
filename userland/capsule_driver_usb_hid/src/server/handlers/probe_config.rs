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

use crate::descriptors::{hid_bindings, write_binding};
use crate::protocol::{
    Request, CONFIG_DESCRIPTOR_MAX, E_INVAL, E_NO_HID, HDR_LEN, HID_BINDING_WIRE_LEN, STATUS_LEN,
};
use crate::server::respond;
use crate::state::State;

pub fn handle(state: &mut State, sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if body.len() > CONFIG_DESCRIPTOR_MAX {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let bindings = match hid_bindings(body) {
        Ok(v) => v,
        Err(_) => {
            let _ = respond::status(sender_pid, req, E_INVAL, tx);
            return;
        }
    };
    if bindings.is_empty() {
        let _ = respond::status(sender_pid, req, E_NO_HID, tx);
        return;
    }
    state.configs_probed = state.configs_probed.wrapping_add(1);
    let base = HDR_LEN + STATUS_LEN;
    tx[base..base + 4].copy_from_slice(&(bindings.len() as u32).to_le_bytes());
    for (i, binding) in bindings.iter().enumerate() {
        let off = base + 4 + i * HID_BINDING_WIRE_LEN;
        write_binding(&mut tx[off..off + HID_BINDING_WIRE_LEN], *binding);
    }
    let body_len = 4 + bindings.len() * HID_BINDING_WIRE_LEN;
    let _ = respond::payload(sender_pid, req, body_len, tx);
}
