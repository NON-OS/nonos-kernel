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

use crate::device::cmd::{self, transfer_to_host_2d::Rect};
use crate::driver::Driver;
use crate::protocol::{Request, E_BUSY, E_DEVICE, E_INVAL, TRANSFER_TO_HOST_REQ_LEN};
use crate::server::respond;

pub fn handle(driver: &Driver, sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if body.len() != TRANSFER_TO_HOST_REQ_LEN {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let resource_id = u32::from_le_bytes(body[0..4].try_into().unwrap());
    let x = u32::from_le_bytes(body[4..8].try_into().unwrap());
    let y = u32::from_le_bytes(body[8..12].try_into().unwrap());
    let w = u32::from_le_bytes(body[12..16].try_into().unwrap());
    let h = u32::from_le_bytes(body[16..20].try_into().unwrap());
    let offset = u64::from_le_bytes(body[24..32].try_into().unwrap());
    let Some(res) = driver.resources.lookup(resource_id) else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    if res.owner_pid != sender_pid {
        let _ = respond::status(sender_pid, req, E_BUSY, tx);
        return;
    }
    if w == 0 || h == 0 || x.saturating_add(w) > res.width || y.saturating_add(h) > res.height {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let fence_id = driver.fences.issue();
    if cmd::transfer_to_host_2d(
        &driver.control_queue,
        fence_id,
        resource_id,
        Rect { x, y, width: w, height: h },
        offset,
    )
    .is_err()
    {
        let _ = respond::status(sender_pid, req, E_DEVICE, tx);
        return;
    }
    let _ = respond::status(sender_pid, req, 0, tx);
}
