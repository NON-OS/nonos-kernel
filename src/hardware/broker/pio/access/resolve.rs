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

//! Resolve a grant for a port-bounded access. Holder lookup,
//! current-claim epoch crosscheck (catches a grant that survived
//! a device re-claim), and bounds against the (port_base,
//! port_count) window. Every kernel-mediated PIO read or write
//! starts here; if any step fails the access is refused.

use super::super::grant::{self, PioGrant};
use super::super::types::{PioError, PioWidth};
use crate::hardware::broker::claim;

pub(super) fn resolve(
    pid: u32,
    grant_id: u64,
    port_offset: u16,
    width: PioWidth,
) -> Result<PioGrant, PioError> {
    let g = grant::lookup_for_holder(pid, grant_id)?;
    let cur = claim::lookup(g.device_id).ok_or(PioError::NotClaimed)?;
    if cur.epoch != g.claim_epoch || cur.pid != pid {
        return Err(PioError::StaleEpoch);
    }
    let end = port_offset
        .checked_add(width.bytes())
        .ok_or(PioError::BadOffset)?;
    if end > g.port_count {
        return Err(PioError::BadOffset);
    }
    let _ = g
        .port_base
        .checked_add(port_offset)
        .ok_or(PioError::BadOffset)?;
    Ok(g)
}
