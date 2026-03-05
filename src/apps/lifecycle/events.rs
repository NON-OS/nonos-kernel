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

use alloc::collections::VecDeque;
use alloc::string::String;
use spin::Mutex;

use crate::apps::types::AppId;

const MAX_EVENTS: usize = 256;

#[derive(Debug, Clone)]
pub enum AppEvent {
    Started { app_id: AppId, name: String },
    Stopped { app_id: AppId, name: String },
    Suspended { app_id: AppId, name: String },
    Resumed { app_id: AppId, name: String },
    Failed { app_id: AppId, name: String, reason: String },
    PermissionGranted { app_id: AppId, permission: u32 },
    PermissionRevoked { app_id: AppId, permission: u32 },
}

impl AppEvent {
    pub fn app_id(&self) -> AppId {
        match self {
            Self::Started { app_id, .. } => *app_id,
            Self::Stopped { app_id, .. } => *app_id,
            Self::Suspended { app_id, .. } => *app_id,
            Self::Resumed { app_id, .. } => *app_id,
            Self::Failed { app_id, .. } => *app_id,
            Self::PermissionGranted { app_id, .. } => *app_id,
            Self::PermissionRevoked { app_id, .. } => *app_id,
        }
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Started { name, .. } => Some(name),
            Self::Stopped { name, .. } => Some(name),
            Self::Suspended { name, .. } => Some(name),
            Self::Resumed { name, .. } => Some(name),
            Self::Failed { name, .. } => Some(name),
            _ => None,
        }
    }
}

static EVENT_QUEUE: Mutex<VecDeque<AppEvent>> = Mutex::new(VecDeque::new());

pub fn emit_event(event: AppEvent) {
    let mut queue = EVENT_QUEUE.lock();
    if queue.len() >= MAX_EVENTS {
        queue.pop_front();
    }
    queue.push_back(event);
}

pub fn poll_event() -> Option<AppEvent> {
    EVENT_QUEUE.lock().pop_front()
}

pub fn peek_event() -> Option<AppEvent> {
    EVENT_QUEUE.lock().front().cloned()
}

pub fn event_count() -> usize {
    EVENT_QUEUE.lock().len()
}

pub fn clear_events() {
    EVENT_QUEUE.lock().clear();
}
