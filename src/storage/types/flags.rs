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

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct IoFlags: u32 {
        const NONE = 0;
        const SYNC = 1 << 0;
        const DIRECT = 1 << 1;
        const FUA = 1 << 2;
        const PRIORITY_HIGH = 1 << 3;
        const PRIORITY_LOW = 1 << 4;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct DeviceCapabilities: u32 {
        const NONE = 0;
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const FLUSH = 1 << 2;
        const TRIM = 1 << 3;
        const SECURE_ERASE = 1 << 4;
        const NCQ = 1 << 5;
        const FUA = 1 << 6;
        const ENCRYPTION = 1 << 7;
        const SMART = 1 << 8;
    }
}
