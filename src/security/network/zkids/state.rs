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

use alloc::collections::BTreeMap;
use spin::{RwLock, Once};
use super::types::{ZkidsManager, ZkidsConfig};

static ZKIDS_MANAGER: Once<RwLock<ZkidsManager>> = Once::new();

pub fn get_zkids_manager() -> &'static RwLock<ZkidsManager> {
    ZKIDS_MANAGER.call_once(|| RwLock::new(ZkidsManager {
        registered_ids: BTreeMap::new(),
        active_sessions: BTreeMap::new(),
        pending_challenges: BTreeMap::new(),
        config: ZkidsConfig::default(),
    }))
}
