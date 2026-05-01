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

use super::base::sbi_call;
use super::error::SbiError;

const EID_IPI: usize = 0x735049;
const FID_SEND_IPI: usize = 0;

pub fn send_ipi(hart_mask: u64) -> Result<(), SbiError> {
    let ret = sbi_call(EID_IPI, FID_SEND_IPI, hart_mask as usize, 0, 0);

    if ret.error != 0 {
        Err(SbiError::from(ret.error))
    } else {
        Ok(())
    }
}

pub fn send_ipi_to_hart(hartid: usize) -> Result<(), SbiError> {
    send_ipi(1 << hartid)
}

pub fn send_ipi_to_all() -> Result<(), SbiError> {
    send_ipi(u64::MAX)
}

pub fn send_ipi_to_others() -> Result<(), SbiError> {
    let self_hart = super::super::cpu::hart_id();
    let mask = u64::MAX & !(1u64 << self_hart);
    send_ipi(mask)
}
