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

use crate::constants::{VG_FORMAT_B8G8R8A8_UNORM, VG_MAX_SCANOUTS};
use crate::device::cmd::{self, transfer_to_host_2d::Rect};
use crate::driver::Driver;
use crate::protocol::{le_u32, Request, E_BUSY, E_DEVICE, E_INVAL, SET_SCANOUT_REQ_LEN};
use crate::server::respond;
use crate::state::Scanout;

pub fn handle(driver: &Driver, sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if body.len() != SET_SCANOUT_REQ_LEN {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let Some(scanout_id) = le_u32(body, 0) else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    let Some(resource_id) = le_u32(body, 4) else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    let Some(x) = le_u32(body, 8) else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    let Some(y) = le_u32(body, 12) else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    let Some(w) = le_u32(body, 16) else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    let Some(h) = le_u32(body, 20) else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    if (scanout_id as usize) >= VG_MAX_SCANOUTS || w == 0 || h == 0 {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let Some(res) = driver.resources.lookup(resource_id) else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    if res.owner_pid != sender_pid {
        let _ = respond::status(sender_pid, req, E_BUSY, tx);
        return;
    }
    if res.format != VG_FORMAT_B8G8R8A8_UNORM {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let fence_id = driver.fences.issue();
    if cmd::set_scanout(
        &driver.control_queue,
        fence_id,
        scanout_id,
        resource_id,
        Rect { x, y, width: w, height: h },
    )
    .is_err()
    {
        let _ = respond::status(sender_pid, req, E_DEVICE, tx);
        return;
    }
    driver.scanouts.record(
        scanout_id,
        Scanout { x, y, width: w, height: h, current_resource_id: resource_id, enabled: true },
    );
    let _ = respond::status(sender_pid, req, 0, tx);
}
