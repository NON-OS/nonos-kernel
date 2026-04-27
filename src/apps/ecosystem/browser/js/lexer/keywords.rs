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

use super::token::TokenKind;

pub(super) fn lookup_keyword(s: &str) -> Option<TokenKind> {
    match s {
        "var" => Some(TokenKind::Var),
        "let" => Some(TokenKind::Let),
        "const" => Some(TokenKind::Const),
        "function" => Some(TokenKind::Function),
        "return" => Some(TokenKind::Return),
        "if" => Some(TokenKind::If),
        "else" => Some(TokenKind::Else),
        "for" => Some(TokenKind::For),
        "while" => Some(TokenKind::While),
        "do" => Some(TokenKind::Do),
        "break" => Some(TokenKind::Break),
        "continue" => Some(TokenKind::Continue),
        "switch" => Some(TokenKind::Switch),
        "case" => Some(TokenKind::Case),
        "default" => Some(TokenKind::Default),
        "try" => Some(TokenKind::Try),
        "catch" => Some(TokenKind::Catch),
        "finally" => Some(TokenKind::Finally),
        "throw" => Some(TokenKind::Throw),
        "new" => Some(TokenKind::New),
        "this" => Some(TokenKind::This),
        "class" => Some(TokenKind::Class),
        "extends" => Some(TokenKind::Extends),
        "super" => Some(TokenKind::Super),
        "static" => Some(TokenKind::Static),
        "get" => Some(TokenKind::Get),
        "set" => Some(TokenKind::Set),
        "import" => Some(TokenKind::Import),
        "export" => Some(TokenKind::Export),
        "from" => Some(TokenKind::From),
        "as" => Some(TokenKind::As),
        "async" => Some(TokenKind::Async),
        "await" => Some(TokenKind::Await),
        "yield" => Some(TokenKind::Yield),
        "of" => Some(TokenKind::Of),
        "in" => Some(TokenKind::In),
        "typeof" => Some(TokenKind::Typeof),
        "instanceof" => Some(TokenKind::Instanceof),
        "void" => Some(TokenKind::Void),
        "delete" => Some(TokenKind::Delete),
        "debugger" => Some(TokenKind::Debugger),
        "with" => Some(TokenKind::With),
        "true" => Some(TokenKind::Boolean(true)),
        "false" => Some(TokenKind::Boolean(false)),
        "null" => Some(TokenKind::Null),
        "undefined" => Some(TokenKind::Undefined),
        _ => None,
    }
}
