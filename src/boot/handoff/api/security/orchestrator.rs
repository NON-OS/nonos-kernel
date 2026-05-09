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

use super::super::super::types::BootHandoffV1;
use super::super::error::HandoffError;
use super::{entropy, entry_point, framebuffer, memory_map};

pub(crate) fn validate_security(handoff: &BootHandoffV1) -> Result<(), HandoffError> {
    entropy::check(handoff)?;
    memory_map::check(handoff)?;
    framebuffer::check(handoff)?;
    entry_point::check(handoff)?;
    Ok(())
}
