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

pub mod bytecode;
pub mod vm;
pub mod vm_ops;
pub mod script;
pub mod script_expr;
pub mod script_ops;
pub mod script_control;
pub mod script_parse;
pub mod compiler;

pub use vm::NoxVM;
pub use script::NoxScript;
pub use bytecode::Bytecode;
