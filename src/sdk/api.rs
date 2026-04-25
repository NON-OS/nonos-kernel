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

use super::app::AppResult;
use super::manifest::AppPermission;

pub trait NetworkAccess {
    fn http_get(&self, url: &[u8]) -> AppResult<alloc::vec::Vec<u8>>;
    fn http_post(&self, url: &[u8], body: &[u8]) -> AppResult<alloc::vec::Vec<u8>>;
}

pub trait StorageAccess {
    fn get(&self, key: &[u8]) -> Option<alloc::vec::Vec<u8>>;
    fn set(&self, key: &[u8], value: &[u8]) -> AppResult<()>;
    fn delete(&self, key: &[u8]) -> AppResult<()>;
    fn list_keys(&self) -> alloc::vec::Vec<alloc::vec::Vec<u8>>;
}

pub trait WalletAccess {
    fn get_address(&self) -> Option<[u8; 20]>;
    fn get_nox_balance(&self) -> u128;
    fn request_payment(&self, to: &[u8; 20], amount_nox: u64) -> AppResult<[u8; 32]>;
}

pub struct SdkApi {
    pub app_id: u32,
    pub permissions: [AppPermission; 8],
    pub perm_count: u8,
}

impl SdkApi {
    pub fn has_permission(&self, p: AppPermission) -> bool {
        for i in 0..self.perm_count as usize {
            if self.permissions[i] == p {
                return true;
            }
        }
        false
    }

    pub fn notify(&self, msg: &[u8]) {
        if self.has_permission(AppPermission::Notifications) {
            crate::graphics::window::notify_info(msg);
        }
    }

    pub fn timestamp(&self) -> u64 {
        crate::time::timestamp_millis()
    }
}
