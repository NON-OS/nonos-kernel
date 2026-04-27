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

pub mod agents;
mod agents_actions;
pub mod apps;
pub mod blockchain;
pub mod builtins;
pub mod core;
pub mod crypto;
pub mod devtools;
mod devtools_build;
mod devtools_project;
mod devtools_publish;
pub mod filesystem;
pub mod git;
pub mod network;
pub mod nox;
pub mod npkg;
pub mod process;
pub mod script;
pub mod system;

pub(crate) use self::core::dispatch;
