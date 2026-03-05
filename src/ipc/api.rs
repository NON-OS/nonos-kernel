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
use super::nonos_channel::{IpcMessage, IPC_BUS};
use super::nonos_message::IpcEnvelope;
use super::nonos_policy::get_policy;
use super::nonos_inbox;

pub fn init() {
    super::nonos_policy::init_default_policies();
}

#[inline]
pub fn init_ipc() {
    init();
}

pub fn send_envelope(envelope: IpcEnvelope, token: &CapabilityToken) -> Result<(), &'static str> {
    if !get_policy().allow_message(&envelope, token) {
        return Err("IPC policy violation: send denied");
    }

    if let Some(channel) = IPC_BUS.find_channel(&envelope.from, &envelope.to) {
        channel.send(IpcMessage::new(&envelope.from, &envelope.to, &envelope.data)?)?;
        Ok(())
    } else {
        Err("No IPC channel found")
    }
}

pub fn open_secure_channel(
    from: &str,
    to: &str,
    token: &CapabilityToken,
) -> Result<(), &'static str> {
    if !get_policy().allow_channel(from, to, token) {
        return Err("IPC policy violation: open_channel denied");
    }
    nonos_inbox::register_inbox(to);
    IPC_BUS.open_channel(from, to, token)
}

#[inline]
pub fn list_routes() -> alloc::vec::Vec<(alloc::string::String, alloc::string::String)> {
    IPC_BUS.list_routes()
}

#[inline]
pub fn get_bus_stats() -> super::nonos_channel::BusStatsSnapshot {
    IPC_BUS.get_stats()
}

#[inline]
pub fn get_policy_stats() -> super::nonos_policy::PolicyStatsSnapshot {
    get_policy().get_stats()
}
