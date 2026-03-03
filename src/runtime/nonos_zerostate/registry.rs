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

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, sync::Arc};
use spin::{RwLock, Once};

use crate::runtime::nonos_capsule::Capsule;
use crate::runtime::nonos_isolation::IsolationState;

pub(super) struct CapsuleRegistry {
    pub(super) by_id: BTreeMap<u64, Arc<Capsule>>,
    pub(super) by_name: BTreeMap<String, u64>,
    pub(super) iso: BTreeMap<u64, IsolationState>,
}

impl CapsuleRegistry {
    pub(super) fn new() -> Self {
        Self {
            by_id: BTreeMap::new(),
            by_name: BTreeMap::new(),
            iso: BTreeMap::new(),
        }
    }
}

static REGISTRY: Once<RwLock<CapsuleRegistry>> = Once::new();

pub(super) fn get_registry() -> &'static RwLock<CapsuleRegistry> {
    REGISTRY.call_once(|| RwLock::new(CapsuleRegistry::new()))
}
