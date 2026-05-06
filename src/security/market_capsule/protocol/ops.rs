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

//! Op discriminants. Adding a new op requires a new constant here,
//! a userland handler under `capsule_market/src/server/handlers/`,
//! and a kernel-side client. Routing is by op number only.

pub(in super::super) const OP_LOAD_INDEX: u16 = 1;
pub(in super::super) const OP_LIST_APPS: u16 = 2;
pub(in super::super) const OP_GET_APP: u16 = 3;
pub(in super::super) const OP_GET_RELEASE: u16 = 4;
pub(in super::super) const OP_INSTALL_READY: u16 = 5;
pub(in super::super) const OP_HEALTHCHECK: u16 = 6;
