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

use super::manifest::AppPermission;
use spin::Mutex;

pub const MAX_GRANTS: usize = 256;

#[derive(Clone, Copy)]
pub struct PermissionGrant {
    pub app_id: u32,
    pub permission: AppPermission,
    pub granted: bool,
    pub granted_at: u64,
}

static GRANTS: Mutex<[PermissionGrant; MAX_GRANTS]> = Mutex::new(
    [PermissionGrant {
        app_id: 0,
        permission: AppPermission::Storage,
        granted: false,
        granted_at: 0,
    }; MAX_GRANTS],
);

pub fn request_permission(app_id: u32, perm: AppPermission) -> bool {
    let mut grants = GRANTS.lock();
    if let Some(g) = grants.iter().find(|g| g.app_id == app_id && g.permission == perm) {
        return g.granted;
    }
    for g in grants.iter_mut() {
        if g.app_id == 0 {
            *g = PermissionGrant {
                app_id,
                permission: perm,
                granted: true,
                granted_at: crate::time::timestamp_millis(),
            };
            return true;
        }
    }
    false
}

pub fn check_permission(app_id: u32, perm: AppPermission) -> bool {
    let grants = GRANTS.lock();
    grants.iter().any(|g| g.app_id == app_id && g.permission == perm && g.granted)
}

pub fn revoke_permission(app_id: u32, perm: AppPermission) -> bool {
    let mut grants = GRANTS.lock();
    for g in grants.iter_mut() {
        if g.app_id == app_id && g.permission == perm {
            g.granted = false;
            return true;
        }
    }
    false
}

pub fn revoke_all(app_id: u32) {
    let mut grants = GRANTS.lock();
    for g in grants.iter_mut() {
        if g.app_id == app_id {
            g.granted = false;
        }
    }
}

pub fn list_permissions(app_id: u32) -> alloc::vec::Vec<AppPermission> {
    let grants = GRANTS.lock();
    grants.iter().filter(|g| g.app_id == app_id && g.granted).map(|g| g.permission).collect()
}
