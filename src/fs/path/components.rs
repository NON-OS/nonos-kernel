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

use super::validate::is_absolute;

pub struct Components<'a> {
    path: &'a str,
    position: usize,
    is_absolute: bool,
    yielded_root: bool,
}

impl<'a> Components<'a> {
    pub fn new(path: &'a str) -> Self {
        Self {
            path,
            position: 0,
            is_absolute: is_absolute(path),
            yielded_root: false,
        }
    }
}

impl<'a> Iterator for Components<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_absolute && !self.yielded_root {
            self.yielded_root = true;
            self.position = 1;
            return Some("/");
        }

        while self.position < self.path.len() {
            if self.path.as_bytes()[self.position] != b'/' {
                break;
            }
            self.position += 1;
        }

        if self.position >= self.path.len() {
            return None;
        }

        let start = self.position;
        while self.position < self.path.len() {
            if self.path.as_bytes()[self.position] == b'/' {
                break;
            }
            self.position += 1;
        }

        Some(&self.path[start..self.position])
    }
}

pub fn components(path: &str) -> Components<'_> {
    Components::new(path)
}

pub fn component_count(path: &str) -> usize {
    components(path).count()
}
