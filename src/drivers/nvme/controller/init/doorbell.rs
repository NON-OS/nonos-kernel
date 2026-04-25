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

use super::super::super::constants::{cap_dstrd, doorbell_cq_offset, doorbell_sq_offset, REG_CAP};
use crate::memory::mmio::mmio_r64;
use x86_64::VirtAddr;

pub fn get_doorbell_stride(mmio_base: usize) -> u32 {
    let cap = mmio_r64(VirtAddr::new((mmio_base + REG_CAP) as u64));
    cap_dstrd(cap)
}

pub fn calculate_sq_doorbell(mmio_base: usize, dstrd: u32, qid: u16) -> usize {
    mmio_base + doorbell_sq_offset(dstrd, qid)
}

pub fn calculate_cq_doorbell(mmio_base: usize, dstrd: u32, qid: u16) -> usize {
    mmio_base + doorbell_cq_offset(dstrd, qid)
}
