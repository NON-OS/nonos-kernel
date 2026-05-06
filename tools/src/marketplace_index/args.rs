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

//! Tiny `--flag value` pair parser. The CLI surface is small and
//! stable enough that a full argument-parser dependency would carry
//! more weight than it earns.

use std::collections::BTreeMap;

pub struct Flags {
    pairs: BTreeMap<String, String>,
}

impl Flags {
    pub fn parse(rest: &[String]) -> Result<Self, String> {
        let mut pairs = BTreeMap::new();
        let mut i = 0;
        while i < rest.len() {
            let key = &rest[i];
            if !key.starts_with("--") {
                return Err(format!("unexpected positional argument: {key}"));
            }
            let value = rest
                .get(i + 1)
                .ok_or_else(|| format!("flag {key} expects a value"))?;
            pairs.insert(key[2..].to_string(), value.clone());
            i += 2;
        }
        Ok(Flags { pairs })
    }

    pub fn require(&self, name: &str) -> Result<&str, String> {
        self.pairs
            .get(name)
            .map(|s| s.as_str())
            .ok_or_else(|| format!("missing required flag --{name}"))
    }

    pub fn optional(&self, name: &str) -> Option<&str> {
        self.pairs.get(name).map(|s| s.as_str())
    }
}
