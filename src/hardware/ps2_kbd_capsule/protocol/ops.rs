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

//! Op discriminants. Adding a new op needs a userland handler at
//! `capsule_driver_ps2_input/src/server/handlers/` and a kernel
//! client; nothing else routes by op.

pub(in super::super) const OP_HEALTHCHECK: u16 = 1;
pub(in super::super) const OP_POLL_EVENTS: u16 = 2;
pub(in super::super) const OP_GET_STATE: u16 = 3;
