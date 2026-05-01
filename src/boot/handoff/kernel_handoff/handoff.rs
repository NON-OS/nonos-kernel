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

use super::arch::ArchSpecificHandoff;
use super::console::EarlyConsole;
use super::cpu::CpuTopology;
use super::framebuffer::Framebuffer;
use super::measurement::Measurement;
use super::memory::MemoryHandoff;
use super::timing::TimingHandoff;

#[derive(Debug, Clone, Copy)]
pub struct KernelHandoff<'a> {
    pub memory: MemoryHandoff,
    pub cpus: CpuTopology,
    pub console: EarlyConsole,
    pub framebuffer: Option<Framebuffer>,
    pub timing: TimingHandoff,
    pub measurement: Measurement,
    pub arch: ArchSpecificHandoff<'a>,
}
