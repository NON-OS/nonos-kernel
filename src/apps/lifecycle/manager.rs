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

use super::events::{emit_event, AppEvent};
use super::state::LifecycleState;
use crate::apps::registry::{get_app_mut, AppEntry};
use crate::apps::types::{AppError, AppId, AppResult, AppType};

pub fn start_app(name: &str) -> AppResult<AppId> {
    get_app_mut(name, |entry: &mut AppEntry| {
        if !entry.state().can_start() {
            return Err(AppError::AlreadyRunning);
        }

        if entry.app_type().requires_network() && !crate::network::is_network_ready() {
            return Err(AppError::NetworkRequired);
        }

        entry.set_state(LifecycleState::Starting);

        let ctx = entry.create_context();
        ctx.mark_started();
        let app_id = ctx.id();

        entry.set_state(LifecycleState::Running);

        emit_event(AppEvent::Started {
            app_id,
            name: String::from(name),
        });

        Ok(app_id)
    })?
}

pub fn stop_app(name: &str) -> AppResult<()> {
    get_app_mut(name, |entry: &mut AppEntry| {
        if !entry.state().can_stop() {
            return Err(AppError::NotRunning);
        }

        let app_id = entry.id().ok_or(AppError::InvalidState)?;

        entry.set_state(LifecycleState::Stopping);
        entry.destroy_context();
        entry.set_state(LifecycleState::Stopped);

        emit_event(AppEvent::Stopped {
            app_id,
            name: String::from(name),
        });

        Ok(())
    })?
}

pub fn suspend_app(name: &str) -> AppResult<()> {
    get_app_mut(name, |entry: &mut AppEntry| {
        if !entry.state().can_suspend() {
            return Err(AppError::InvalidState);
        }

        let app_id = entry.id().ok_or(AppError::InvalidState)?;

        entry.set_state(LifecycleState::Suspended);

        emit_event(AppEvent::Suspended {
            app_id,
            name: String::from(name),
        });

        Ok(())
    })?
}

pub fn resume_app(name: &str) -> AppResult<()> {
    get_app_mut(name, |entry: &mut AppEntry| {
        if !entry.state().can_resume() {
            return Err(AppError::InvalidState);
        }

        let app_id = entry.id().ok_or(AppError::InvalidState)?;

        if let Some(ctx) = entry.context_mut() {
            ctx.mark_active();
        }

        entry.set_state(LifecycleState::Running);

        emit_event(AppEvent::Resumed {
            app_id,
            name: String::from(name),
        });

        Ok(())
    })?
}

pub fn restart_app(name: &str) -> AppResult<AppId> {
    let _ = stop_app(name);
    start_app(name)
}

pub fn get_app_type(name: &str) -> AppResult<AppType> {
    get_app_mut(name, |entry: &mut AppEntry| {
        Ok(entry.app_type())
    })?
}

pub fn is_network_app(name: &str) -> bool {
    get_app_type(name)
        .map(|t| t.requires_network())
        .unwrap_or(false)
}

pub fn fail_app(name: &str, reason: &str) -> AppResult<()> {
    get_app_mut(name, |entry: &mut AppEntry| {
        let app_id = entry.id().unwrap_or(AppId::SYSTEM);

        entry.destroy_context();
        entry.set_state(LifecycleState::Failed);

        emit_event(AppEvent::Failed {
            app_id,
            name: String::from(name),
            reason: String::from(reason),
        });

        Ok(())
    })?
}
