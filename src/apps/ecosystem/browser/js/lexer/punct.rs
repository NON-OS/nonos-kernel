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

use super::scanner::Lexer;
use super::token::TokenKind;

impl<'a> Lexer<'a> {
    pub fn scan_punct(&mut self) -> TokenKind {
        let Some(c) = self.advance() else { return TokenKind::Invalid; };
        match c {
            '(' => TokenKind::LParen, ')' => TokenKind::RParen,
            '{' => TokenKind::LBrace, '}' => TokenKind::RBrace,
            '[' => TokenKind::LBracket, ']' => TokenKind::RBracket,
            ',' => TokenKind::Comma, ':' => TokenKind::Colon, ';' => TokenKind::Semi, '?' => TokenKind::Question,
            '~' => TokenKind::Tilde,
            '.' => if self.peek() == Some('.') && self.peek_n(1) == Some('.') { self.advance(); self.advance(); TokenKind::Spread } else { TokenKind::Dot },
            '+' => if self.peek() == Some('+') { self.advance(); TokenKind::PlusPlus } else if self.peek() == Some('=') { self.advance(); TokenKind::PlusEq } else { TokenKind::Plus },
            '-' => if self.peek() == Some('-') { self.advance(); TokenKind::MinusMinus } else if self.peek() == Some('=') { self.advance(); TokenKind::MinusEq } else { TokenKind::Minus },
            '*' => if self.peek() == Some('*') { self.advance(); TokenKind::StarStar } else if self.peek() == Some('=') { self.advance(); TokenKind::StarEq } else { TokenKind::Star },
            '/' => if self.peek() == Some('=') { self.advance(); TokenKind::SlashEq } else { TokenKind::Slash },
            '%' => if self.peek() == Some('=') { self.advance(); TokenKind::PercentEq } else { TokenKind::Percent },
            '=' => if self.peek() == Some('=') { self.advance(); if self.peek() == Some('=') { self.advance(); TokenKind::EqEqEq } else { TokenKind::EqEq } } else if self.peek() == Some('>') { self.advance(); TokenKind::Arrow } else { TokenKind::Eq },
            '!' => if self.peek() == Some('=') { self.advance(); if self.peek() == Some('=') { self.advance(); TokenKind::BangEqEq } else { TokenKind::BangEq } } else { TokenKind::Bang },
            '<' => if self.peek() == Some('=') { self.advance(); TokenKind::LtEq } else if self.peek() == Some('<') { self.advance(); TokenKind::LtLt } else { TokenKind::Lt },
            '>' => if self.peek() == Some('=') { self.advance(); TokenKind::GtEq } else if self.peek() == Some('>') { self.advance(); if self.peek() == Some('>') { self.advance(); TokenKind::GtGtGt } else { TokenKind::GtGt } } else { TokenKind::Gt },
            '&' => if self.peek() == Some('&') { self.advance(); TokenKind::AmpAmp } else if self.peek() == Some('=') { self.advance(); TokenKind::AmpEq } else { TokenKind::Amp },
            '|' => if self.peek() == Some('|') { self.advance(); TokenKind::PipePipe } else if self.peek() == Some('=') { self.advance(); TokenKind::PipeEq } else { TokenKind::Pipe },
            '^' => if self.peek() == Some('=') { self.advance(); TokenKind::CaretEq } else { TokenKind::Caret },
            _ => TokenKind::Invalid,
        }
    }
}
