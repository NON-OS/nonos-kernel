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

use crate::syscall::capabilities::CapabilityToken;

use super::registry::get_registry;
use super::capsule_ops::get_capsule_by_name;

pub fn send_from_capsule(
    from: &str,
    to: &'static str,
    payload: &[u8],
    token: &CapabilityToken,
) -> Result<(), &'static str> {
    let (cap, iso_result) = {
        let reg = get_registry().read();
        let id = reg.by_name.get(from).copied().ok_or("capsule not found")?;
        let cap = reg.by_id.get(&id).cloned().ok_or("capsule missing")?;
        let iso = reg.iso.get(&id).ok_or("isolation missing")?;

        let iso_result = iso.check_inbox_capacity()
            .and_then(|_| iso.charge_message(payload.len()));

        (cap, iso_result)
    };

    iso_result?;
    cap.send(to, payload, token)
}

pub fn poll_capsule(name: &str) -> Option<crate::ipc::nonos_channel::IpcMessage> {
    let cap = get_capsule_by_name(name)?;
    cap.recv()
}

pub fn heartbeat(name: &str) {
    if let Some(cap) = get_capsule_by_name(name) {
        cap.heartbeat();
    }
}
