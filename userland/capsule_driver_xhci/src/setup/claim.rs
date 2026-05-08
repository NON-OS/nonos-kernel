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

//! Device-claim phase. The broker returns the per-claim epoch as
//! the syscall's positive return value; subsequent grant calls
//! quote it back so a foreign re-claim is detected as a stale
//! epoch by the broker. There is no prior grant to roll back if
//! this phase fails.

use nonos_libc::mk_device_claim;

use crate::error::{XhciError, XhciResult};

pub fn claim(device_id: u64) -> XhciResult<u64> {
    let r = mk_device_claim(device_id);
    if r < 0 {
        return Err(XhciError::BrokerCallFailed(r));
    }
    Ok(r as u64)
}
