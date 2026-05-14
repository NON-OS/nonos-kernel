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

use core::sync::atomic::Ordering;

use super::discover;
use crate::l2_client::{read_mac, MacError};
use crate::state::STATE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupError {
    L2NotFound,
    IpNotFound,
    L2MacFailed,
}

impl From<discover::DiscoverError> for SetupError {
    fn from(_: discover::DiscoverError) -> Self {
        Self::L2NotFound
    }
}

impl From<MacError> for SetupError {
    fn from(_: MacError) -> Self {
        Self::L2MacFailed
    }
}

// Cache L2 and IP service ports, read the NIC MAC. Any failure
// terminates the capsule because every subsequent op depends on
// both services being reachable.
pub fn run() -> Result<(), SetupError> {
    let l2_port = discover::net_l2()?;
    STATE.l2_port.store(l2_port, Ordering::Release);

    let ip_port = discover::net_ip().map_err(|_| SetupError::IpNotFound)?;
    STATE.ip_port.store(ip_port, Ordering::Release);

    let mac = read_mac(l2_port)?;
    *STATE.mac.lock() = mac;
    Ok(())
}
