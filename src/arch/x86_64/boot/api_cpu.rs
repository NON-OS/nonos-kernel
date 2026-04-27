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

use super::types::CpuFeatures;

#[inline]
pub fn cpu_features() -> CpuFeatures {
    crate::arch::x86_64::cpu::features()
}

#[inline]
pub fn cpu_family() -> u8 {
    crate::arch::x86_64::cpu::cpu_id().family
}

#[inline]
pub fn cpu_model() -> u8 {
    crate::arch::x86_64::cpu::cpu_id().model
}

#[inline]
pub fn cpu_stepping() -> u8 {
    crate::arch::x86_64::cpu::cpu_id().stepping
}
