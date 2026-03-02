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

use alloc::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleState {
    Unloaded,
    Loading,
    Loaded,
    Running,
    Paused,
    Stopping,
    Stopped,
    Failed,
}

impl Default for ModuleState {
    fn default() -> Self {
        Self::Unloaded
    }
}

impl ModuleState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unloaded => "Unloaded",
            Self::Loading => "Loading",
            Self::Loaded => "Loaded",
            Self::Running => "Running",
            Self::Paused => "Paused",
            Self::Stopping => "Stopping",
            Self::Stopped => "Stopped",
            Self::Failed => "Failed",
        }
    }

    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Running | Self::Paused)
    }

    pub const fn can_start(&self) -> bool {
        matches!(self, Self::Loaded | Self::Stopped | Self::Paused)
    }

    pub const fn can_stop(&self) -> bool {
        matches!(self, Self::Running | Self::Paused)
    }
}

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub id: u64,
    pub name: String,
    pub state: ModuleState,
    pub entry_point: Option<usize>,
    pub memory_base: usize,
    pub memory_size: usize,
    pub load_time: u64,
    pub params: Option<String>,
}

impl ModuleInfo {
    pub fn new(id: u64, name: String) -> Self {
        Self {
            id,
            name,
            state: ModuleState::Unloaded,
            entry_point: None,
            memory_base: 0,
            memory_size: 0,
            load_time: 0,
            params: None,
        }
    }

    pub fn with_params(mut self, params: String) -> Self {
        self.params = Some(params);
        self
    }

    pub const fn is_loaded(&self) -> bool {
        !matches!(self.state, ModuleState::Unloaded | ModuleState::Failed)
    }

    pub const fn is_running(&self) -> bool {
        matches!(self.state, ModuleState::Running)
    }
}
