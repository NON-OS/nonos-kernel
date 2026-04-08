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

use super::error::CpuError;
use super::msr_core::{rdmsr, wrmsr};

pub fn try_rdmsr(msr: u32) -> Result<u64, CpuError> {
    if msr > 0xC0002FFF && msr < 0xC0010000 {
        return Err(CpuError::InvalidMsr);
    }
    Ok(rdmsr(msr))
}

pub fn try_wrmsr(msr: u32, value: u64) -> Result<(), CpuError> {
    if msr > 0xC0002FFF && msr < 0xC0010000 {
        return Err(CpuError::InvalidMsr);
    }
    wrmsr(msr, value);
    Ok(())
}
