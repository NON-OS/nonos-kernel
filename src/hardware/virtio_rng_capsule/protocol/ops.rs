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

//! Op discriminants. The kernel client only initiates these two
//! ops today; new ops require a matching userland handler under
//! `capsule_driver_virtio_rng/src/server/handlers/`.

pub(in super::super) const OP_FILL_RANDOM: u16 = 1;
pub(in super::super) const OP_HEALTHCHECK: u16 = 2;
