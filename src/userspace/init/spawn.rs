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

use crate::process::core::{create_process, Pid, Priority, ProcessState};

pub fn spawn_service(name: &str) -> Result<Pid, SpawnError> {
    let pid = create_process(name, ProcessState::Ready, Priority::Normal)?;
    Ok(pid)
}

#[derive(Debug, Clone, Copy)]
pub enum SpawnError {
    Failed,
}

impl From<&'static str> for SpawnError {
    fn from(_: &'static str) -> Self {
        SpawnError::Failed
    }
}
