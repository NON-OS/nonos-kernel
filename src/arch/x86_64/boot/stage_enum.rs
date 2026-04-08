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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum BootStage {
    Entry = 0,
    SerialInit = 1,
    VgaInit = 2,
    CpuDetect = 3,
    GdtSetup = 4,
    SegmentReload = 5,
    SseEnable = 6,
    IdtSetup = 7,
    MemoryValidation = 8,
    KernelTransfer = 9,
    Complete = 10,
}

impl BootStage {
    pub const COUNT: usize = 11;
}

impl Default for BootStage {
    fn default() -> Self {
        Self::Entry
    }
}

impl core::fmt::Display for BootStage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
