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

use super::api::{SdkApi, StorageAccess};
use super::app::{AppError, AppResult};
use super::manifest::AppPermission;
use super::storage::AppStorage;
use alloc::vec::Vec;

impl StorageAccess for SdkApi {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        if !self.has_permission(AppPermission::Storage) {
            return None;
        }
        let storage = AppStorage::new(self.app_id);
        storage.get(key)
    }

    fn set(&self, key: &[u8], value: &[u8]) -> AppResult<()> {
        if !self.has_permission(AppPermission::Storage) {
            return Err(AppError::PermissionDenied);
        }
        let storage = AppStorage::new(self.app_id);
        if storage.set(key, value) {
            Ok(())
        } else {
            Err(AppError::StorageFull)
        }
    }

    fn delete(&self, key: &[u8]) -> AppResult<()> {
        if !self.has_permission(AppPermission::Storage) {
            return Err(AppError::PermissionDenied);
        }
        let storage = AppStorage::new(self.app_id);
        storage.delete(key);
        Ok(())
    }

    fn list_keys(&self) -> Vec<Vec<u8>> {
        if !self.has_permission(AppPermission::Storage) {
            return Vec::new();
        }
        let storage = AppStorage::new(self.app_id);
        storage.list_keys()
    }
}
