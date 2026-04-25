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

use super::fadt_struct::Fadt;
use super::flags::boot_flags;

impl Fadt {
    pub fn has_8042(&self) -> bool {
        self.boot_architecture_flags & boot_flags::HAS_8042 != 0
    }
    pub fn has_legacy_devices(&self) -> bool {
        self.boot_architecture_flags & boot_flags::LEGACY_DEVICES != 0
    }
    pub fn has_vga(&self) -> bool {
        self.boot_architecture_flags & boot_flags::NO_VGA == 0
    }
    pub fn has_msi(&self) -> bool {
        self.boot_architecture_flags & boot_flags::NO_MSI == 0
    }
    pub fn has_cmos_rtc(&self) -> bool {
        self.boot_architecture_flags & boot_flags::NO_CMOS_RTC == 0
    }
}
