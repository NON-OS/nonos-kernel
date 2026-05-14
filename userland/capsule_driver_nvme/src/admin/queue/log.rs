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

use super::AdminQueue;
use crate::admin::Submission;
use crate::error::NvmeResult;
use crate::regs::Regs;

const SMART_HEALTH_LID: u8 = 0x02;
const SMART_HEALTH_NSID: u32 = 0xffff_ffff;
const SMART_HEALTH_BYTES: u32 = 512;

impl AdminQueue {
    pub fn smart_health(&mut self, regs: Regs, stride: u8) -> NvmeResult<&[u8]> {
        let cid = self.cid;
        self.cid = self.cid.wrapping_add(1).max(1);
        self.submit(
            regs,
            stride,
            Submission::get_log_page(
                cid,
                SMART_HEALTH_NSID,
                SMART_HEALTH_LID,
                SMART_HEALTH_BYTES,
                self.identify.device_addr(),
            ),
        );
        self.wait(regs, stride, cid)?;
        Ok(unsafe {
            core::slice::from_raw_parts(
                self.identify.user_va() as *const u8,
                SMART_HEALTH_BYTES as usize,
            )
        })
    }
}
