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

use crate::dhcp::Message;
use crate::ip_client::{apply_lease, ApplyError};

use super::mask::mask_to_prefix;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallError {
    BadMask,
    IpRefused,
}

// Push the ACK contents into `net.ip` via OP_SET_CONFIG. The DNS
// stays in capsule state (caller pulls it with LEASE_STATUS); the
// IP capsule itself does not yet host a DNS resolver field.
pub fn install(ip_port: u32, ack: &Message) -> Result<u8, InstallError> {
    let prefix = mask_to_prefix(&ack.subnet_mask).ok_or(InstallError::BadMask)?;
    apply_lease(ip_port, ack.yiaddr, prefix, ack.router).map_err(|e| match e {
        ApplyError::SendFailed | ApplyError::BadResponse | ApplyError::Refused(_) => {
            InstallError::IpRefused
        }
    })?;
    Ok(prefix)
}
