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

use super::answer::Answer;
use super::error::ParseError;
use super::record::read_answer;
use crate::dns::{skip, Header, HDR_LEN, TYPE_A, TYPE_AAAA};

pub fn first_address(message: &[u8]) -> Result<(Header, Option<Answer>), ParseError> {
    let header = Header::parse(message).ok_or(ParseError::Truncated)?;
    if !header.is_response() {
        return Err(ParseError::NotAResponse);
    }
    let pos = skip_questions(message, HDR_LEN, header.qdcount)?;
    parse_answers(message, pos, header)
}

fn skip_questions(message: &[u8], mut pos: usize, qdcount: u16) -> Result<usize, ParseError> {
    for _ in 0..qdcount {
        pos = skip(message, pos)?;
        if pos + 4 > message.len() {
            return Err(ParseError::Truncated);
        }
        pos += 4;
    }
    Ok(pos)
}

fn parse_answers(
    message: &[u8],
    mut pos: usize,
    header: Header,
) -> Result<(Header, Option<Answer>), ParseError> {
    for _ in 0..header.ancount {
        pos = skip(message, pos)?;
        let (answer, next) = read_answer(message, pos)?;
        if answer.rtype == TYPE_A || answer.rtype == TYPE_AAAA {
            return Ok((header, Some(answer)));
        }
        pos = next;
    }
    Ok((header, None))
}
