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

use crate::nox::output::Output;
use crate::nox::tap::Tap;
use crate::nox::{NoxError, NoxResult};
use alloc::string::String;
use alloc::vec::Vec;

pub fn cmd_tap(name: &str, url: Option<&str>) -> NoxResult<Tap> {
    let tap = if let Some(u) = url {
        Tap::from_url(u).ok_or_else(|| NoxError::ParseError(String::from("invalid URL")))?
    } else {
        let parts: Vec<&str> = name.split('/').collect();
        if parts.len() != 2 {
            return Err(NoxError::ParseError(String::from("use user/repo format")));
        }
        Tap::new(parts[0], parts[1])
    };
    let msg = Output::arrow_green(&alloc::format!("Tapping {}", tap.name()));
    crate::drivers::console::write_message(&msg);
    Ok(tap)
}

pub fn cmd_untap(name: &str) -> NoxResult<()> {
    let msg = Output::arrow_yellow(&alloc::format!("Untapping {}", name));
    crate::drivers::console::write_message(&msg);
    Ok(())
}

pub fn cmd_taps() -> NoxResult<Vec<String>> {
    Ok(Vec::new())
}
