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

//! Bring the device through the virtio init handshake on the
//! legacy register window: ACK -> DRIVER -> features -> queue
//! select -> queue PFN -> DRIVER_OK. Refuse to drive anything
//! that does not advertise a usable requestq.

use super::constants::{
    LEG_GUEST_FEATURES, LEG_HOST_FEATURES, LEG_QUEUE_NUM, LEG_QUEUE_PFN, LEG_QUEUE_SEL,
    LEG_STATUS, STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FAILED,
    STATUS_FEATURES_OK,
};
use super::regs::Regs;

pub fn bring_up(regs: Regs, queue_phys: u64, queue_size_hint: u16) -> Result<u16, &'static str> {
    unsafe {
        regs.w8(LEG_STATUS, 0);
        regs.w8(LEG_STATUS, STATUS_ACKNOWLEDGE);
        let s = regs.r8(LEG_STATUS);
        regs.w8(LEG_STATUS, s | STATUS_DRIVER);

        // Negotiate no extra features. virtio-rng does not require
        // any feature bits to function; clearing GUEST_FEATURES
        // keeps the contract tight.
        let _host = regs.r32(LEG_HOST_FEATURES);
        regs.w32(LEG_GUEST_FEATURES, 0);

        let s2 = regs.r8(LEG_STATUS);
        regs.w8(LEG_STATUS, s2 | STATUS_FEATURES_OK);
        let s3 = regs.r8(LEG_STATUS);
        if s3 & STATUS_FEATURES_OK == 0 {
            regs.w8(LEG_STATUS, s3 | STATUS_FAILED);
            return Err("virtio: features-ok rejected");
        }

        regs.w16(LEG_QUEUE_SEL, 0);
        let qmax = regs.r16(LEG_QUEUE_NUM);
        if qmax == 0 {
            regs.w8(LEG_STATUS, regs.r8(LEG_STATUS) | STATUS_FAILED);
            return Err("virtio: requestq missing");
        }
        let qsize = core::cmp::min(qmax, queue_size_hint);

        // Legacy queue PFN is the page index, not the byte address.
        let pfn = (queue_phys >> 12) as u32;
        regs.w32(LEG_QUEUE_PFN, pfn);

        regs.w8(LEG_STATUS, regs.r8(LEG_STATUS) | STATUS_DRIVER_OK);
        Ok(qsize)
    }
}
