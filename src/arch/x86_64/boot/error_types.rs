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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BootError {
    None = 0, SerialInitFailed = 1, VgaInitFailed = 2, CpuInitFailed = 3,
    NoCpuid = 4, NoLongMode = 5, NoSse = 6, NoSse2 = 7, NoFxsr = 8,
    NoApic = 9, NoMsr = 10, NoPae = 11, GdtInitFailed = 12, GdtLoadFailed = 13,
    TssLoadFailed = 14, IdtInitFailed = 15, IdtLoadFailed = 16, SseEnableFailed = 17,
    InvalidPageTable = 18, PagingNotEnabled = 19, PaeNotEnabled = 20, LongModeNotActive = 21,
    NoHigherHalf = 22, MemoryValidationFailed = 23, StackSetupFailed = 24, Timeout = 25,
    NoSmap = 26, NoSmep = 27, NoNx = 28, ApicInitFailed = 29, TimerInitFailed = 30,
    AcpiInitFailed = 31, Unknown = 255,
}

impl Default for BootError { fn default() -> Self { Self::None } }
impl core::fmt::Display for BootError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { write!(f, "{}", self.as_str()) }
}
