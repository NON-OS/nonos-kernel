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

#[derive(Debug, Clone, Copy, Default)]
pub struct PagePermissions {
    pub writable: bool,
    pub user_accessible: bool,
    pub executable: bool,
    pub cache_disabled: bool,
}

impl PagePermissions {
    pub const fn kernel_ro() -> Self {
        Self { writable: false, user_accessible: false, executable: false, cache_disabled: false }
    }

    pub const fn kernel_rw() -> Self {
        Self { writable: true, user_accessible: false, executable: false, cache_disabled: false }
    }

    pub const fn kernel_rx() -> Self {
        Self { writable: false, user_accessible: false, executable: true, cache_disabled: false }
    }

    pub const fn device() -> Self {
        Self { writable: true, user_accessible: false, executable: false, cache_disabled: true }
    }
}
