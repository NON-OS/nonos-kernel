// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::error::BootError;
use super::stage::BootStage;
use super::state;
use super::types::CpuFeatures;
use super::validation::{self, SimdSupport};

#[inline]
pub fn boot_stage() -> BootStage {
    state::get_stage()
}

#[inline]
pub fn boot_error() -> BootError {
    state::get_error()
}

#[inline]
pub fn is_boot_complete() -> bool {
    state::is_complete()
}

#[inline]
pub fn boot_tsc() -> u64 {
    state::get_boot_tsc()
}

#[inline]
pub fn cpu_features() -> CpuFeatures {
    crate::arch::x86_64::cpu::features()
}

#[inline]
pub fn cpu_family() -> u8 {
    let id = crate::arch::x86_64::cpu::cpu_id();
    id.family
}

#[inline]
pub fn cpu_model() -> u8 {
    let id = crate::arch::x86_64::cpu::cpu_id();
    id.model
}

#[inline]
pub fn cpu_stepping() -> u8 {
    let id = crate::arch::x86_64::cpu::cpu_id();
    id.stepping
}

#[inline]
pub fn kernel_stack() -> u64 {
    crate::arch::x86_64::gdt::get_kernel_stack(0).unwrap_or(0)
}

#[inline]
pub fn exception_count() -> u64 {
    state::get_exception_count()
}

#[inline]
pub fn increment_exception_count() {
    state::increment_exception_count()
}

#[inline]
pub fn simd_support() -> SimdSupport {
    validation::get_simd_support()
}
