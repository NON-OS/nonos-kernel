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

//! Operator key handling. Private material is held in
//! [`operator::OperatorKey`] for the duration of the call and never
//! written to stdout, stderr, or any output file. Pubkeys and
//! signatures are the only things the CLI ever emits.

mod operator;
mod parse;
mod verify;

pub use operator::OperatorKey;
pub use parse::parse_pubkey;
pub use verify::verify_signature;
