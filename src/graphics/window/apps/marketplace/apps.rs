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

use super::state::CAT_ALL;
use crate::sdk::registry::{list_apps, AppInfo};
use alloc::vec::Vec;

#[derive(Clone, Copy)]
pub(super) struct AppEntry {
    pub(super) name: [u8; 64],
    pub(super) nox_fee: u32,
    pub(super) installs: u32,
}

impl AppEntry {
    pub(super) fn from_info(info: &AppInfo) -> Self {
        Self {
            name: info.manifest.name,
            nox_fee: info.manifest.price_nox,
            installs: info.run_count,
        }
    }
}

pub(super) fn get_apps(cat: u8) -> Vec<AppEntry> {
    let apps = list_apps();
    if cat == CAT_ALL {
        apps.iter().map(AppEntry::from_info).collect()
    } else {
        apps.iter().filter(|a| a.manifest.category == cat).map(AppEntry::from_info).collect()
    }
}

pub(super) fn app_count(cat: u8) -> usize {
    if cat == CAT_ALL {
        list_apps().len()
    } else {
        list_apps().iter().filter(|a| a.manifest.category == cat).count()
    }
}
