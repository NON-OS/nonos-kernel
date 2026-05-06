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

//! Compile-time trust list for marketplace operator pubkeys. The
//! capsule refuses every signed index whose embedded
//! `operator_pubkey` is not in this list, even if the Ed25519
//! signature itself validates. Rotating the list is a kernel image
//! rebuild — there is no runtime add or remove.

mod check;
mod keys;

pub use check::is_trusted;
