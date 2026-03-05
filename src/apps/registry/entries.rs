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

//! Application registry entry types.

extern crate alloc;

use alloc::string::String;

use crate::apps::context::{AppContext, AppPermissions};
use crate::apps::lifecycle::LifecycleState;
use crate::apps::types::{AppId, AppType};

pub struct AppInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
    pub author: &'static str,
    pub app_type: AppType,
    pub permissions: AppPermissions,
}

impl AppInfo {
    pub const fn new(
        name: &'static str,
        version: &'static str,
        description: &'static str,
        author: &'static str,
        app_type: AppType,
        permissions: AppPermissions,
    ) -> Self {
        Self {
            name,
            version,
            description,
            author,
            app_type,
            permissions,
        }
    }
}

pub struct AppEntry {
    info: AppInfo,
    context: Option<AppContext>,
    state: LifecycleState,
    registered_at: u64,
}

impl AppEntry {
    pub fn new(info: AppInfo) -> Self {
        Self {
            info,
            context: None,
            state: LifecycleState::Stopped,
            registered_at: crate::time::timestamp_millis(),
        }
    }

    pub const fn info(&self) -> &AppInfo {
        &self.info
    }

    pub fn name(&self) -> &str {
        self.info.name
    }

    pub fn version(&self) -> &str {
        self.info.version
    }

    pub fn description(&self) -> &str {
        self.info.description
    }

    pub fn app_type(&self) -> AppType {
        self.info.app_type
    }

    pub fn permissions(&self) -> AppPermissions {
        self.info.permissions
    }

    pub const fn state(&self) -> LifecycleState {
        self.state
    }

    pub fn set_state(&mut self, state: LifecycleState) {
        self.state = state;
    }

    pub fn is_running(&self) -> bool {
        matches!(self.state, LifecycleState::Running | LifecycleState::Suspended)
    }

    pub fn context(&self) -> Option<&AppContext> {
        self.context.as_ref()
    }

    pub fn context_mut(&mut self) -> Option<&mut AppContext> {
        self.context.as_mut()
    }

    pub fn id(&self) -> Option<AppId> {
        self.context.as_ref().map(|c| c.id())
    }

    pub fn create_context(&mut self) -> &mut AppContext {
        let ctx = AppContext::new(
            String::from(self.info.name),
            self.info.app_type,
            self.info.permissions,
        );
        self.context = Some(ctx);
        // SAFETY: We just assigned Some(ctx) above, so this cannot be None
        match self.context.as_mut() {
            Some(c) => c,
            None => unreachable!(),
        }
    }

    pub fn destroy_context(&mut self) {
        self.context = None;
    }

    pub fn registered_at(&self) -> u64 {
        self.registered_at
    }

    pub fn uptime_ms(&self) -> u64 {
        self.context.as_ref().map(|c| c.uptime_ms()).unwrap_or(0)
    }
}
