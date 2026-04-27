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

use super::error_types::BootError;

impl BootError {
    pub const fn is_fatal(self) -> bool {
        !matches!(self, Self::None)
    }

    pub const fn is_cpu_related(self) -> bool {
        matches!(
            self,
            Self::CpuInitFailed
                | Self::NoCpuid
                | Self::NoLongMode
                | Self::NoSse
                | Self::NoSse2
                | Self::NoFxsr
                | Self::NoApic
                | Self::NoMsr
                | Self::NoPae
                | Self::NoSmap
                | Self::NoSmep
                | Self::NoNx
        )
    }

    pub const fn is_memory_related(self) -> bool {
        matches!(
            self,
            Self::InvalidPageTable
                | Self::PagingNotEnabled
                | Self::PaeNotEnabled
                | Self::LongModeNotActive
                | Self::NoHigherHalf
                | Self::MemoryValidationFailed
                | Self::StackSetupFailed
        )
    }
}
