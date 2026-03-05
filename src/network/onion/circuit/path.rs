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

//! Path selection for circuit building

use alloc::vec::Vec;
use crate::network::onion::OnionError;
use crate::network::onion::directory::RelayDescriptor;
use super::types::PathConstraints;

pub(super) struct PathSelector;

impl PathSelector {
    pub(super) fn new() -> Self {
        Self
    }

    pub(super) fn init(&self) -> Result<(), OnionError> {
        Ok(())
    }

    pub(super) fn select_optimal_path(&self, constraints: &PathConstraints) -> Result<Vec<RelayDescriptor>, OnionError> {
        let router_guard = super::super::get_onion_router();
        let router_lock = router_guard.lock();

        if let Some(ref router) = *router_lock {
            router.directory_service.select_path_with_constraints(constraints)
        } else {
            Err(OnionError::DirectoryError)
        }
    }
}
