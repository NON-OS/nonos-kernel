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

pub mod types;
pub mod lexer;
pub mod parser;
pub mod eval;
pub mod builtins;

pub(crate) use lexer::tokenize;
pub(crate) use parser::parse;
pub(crate) use eval::execute;

pub fn run_script(source: &str) {
    let tokens = tokenize(source);
    let stmts = parse(&tokens);
    execute(&stmts);
}
