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

//! Application permission management.

use core::sync::atomic::{AtomicU32, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PermissionLevel {
    Denied = 0,
    ReadOnly = 1,
    ReadWrite = 2,
    Full = 3,
}

impl PermissionLevel {
    pub const fn can_read(self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite | Self::Full)
    }

    pub const fn can_write(self) -> bool {
        matches!(self, Self::ReadWrite | Self::Full)
    }

    pub const fn is_full(self) -> bool {
        matches!(self, Self::Full)
    }
}

impl Default for PermissionLevel {
    fn default() -> Self {
        Self::Denied
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AppPermissions: u32 {
        const NONE = 0;
        const NETWORK = 1 << 0;
        const FILESYSTEM = 1 << 1;
        const CRYPTO = 1 << 2;
        const WALLET = 1 << 3;
        const DISPLAY = 1 << 4;
        const INPUT = 1 << 5;
        const CLIPBOARD = 1 << 6;
        const NOTIFICATIONS = 1 << 7;
        const AUDIO = 1 << 8;
        const USB = 1 << 9;
        const BLUETOOTH = 1 << 10;
        const LOCATION = 1 << 11;
        const CAMERA = 1 << 12;
        const PROCESS = 1 << 13;
        const SYSTEM = 1 << 14;
        const IPC = 1 << 15;

        const BROWSER = Self::NETWORK.bits() | Self::DISPLAY.bits() | Self::INPUT.bits() | Self::CLIPBOARD.bits();
        const WALLET_APP = Self::CRYPTO.bits() | Self::WALLET.bits() | Self::DISPLAY.bits() | Self::INPUT.bits() | Self::FILESYSTEM.bits();
        const ECOSYSTEM = Self::NETWORK.bits() | Self::CRYPTO.bits() | Self::WALLET.bits() | Self::DISPLAY.bits() | Self::INPUT.bits() | Self::CLIPBOARD.bits() | Self::FILESYSTEM.bits() | Self::NOTIFICATIONS.bits();
        const ALL = u32::MAX;
    }
}

impl Default for AppPermissions {
    fn default() -> Self {
        Self::NONE
    }
}

pub struct PermissionManager {
    granted: AtomicU32,
    requested: AtomicU32,
}

impl PermissionManager {
    pub const fn new() -> Self {
        Self {
            granted: AtomicU32::new(0),
            requested: AtomicU32::new(0),
        }
    }

    pub fn grant(&self, perms: AppPermissions) {
        self.granted.fetch_or(perms.bits(), Ordering::Release);
    }

    pub fn revoke(&self, perms: AppPermissions) {
        self.granted.fetch_and(!perms.bits(), Ordering::Release);
    }

    pub fn request(&self, perms: AppPermissions) {
        self.requested.fetch_or(perms.bits(), Ordering::Release);
    }

    pub fn has(&self, perm: AppPermissions) -> bool {
        let granted = AppPermissions::from_bits_truncate(self.granted.load(Ordering::Acquire));
        granted.contains(perm)
    }

    pub fn granted(&self) -> AppPermissions {
        AppPermissions::from_bits_truncate(self.granted.load(Ordering::Acquire))
    }

    pub fn requested(&self) -> AppPermissions {
        AppPermissions::from_bits_truncate(self.requested.load(Ordering::Acquire))
    }

    pub fn pending(&self) -> AppPermissions {
        let req = self.requested.load(Ordering::Acquire);
        let grant = self.granted.load(Ordering::Acquire);
        AppPermissions::from_bits_truncate(req & !grant)
    }

    pub fn reset(&self) {
        self.granted.store(0, Ordering::Release);
        self.requested.store(0, Ordering::Release);
    }
}

impl Default for PermissionManager {
    fn default() -> Self {
        Self::new()
    }
}
