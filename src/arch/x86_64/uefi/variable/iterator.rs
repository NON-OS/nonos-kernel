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

use alloc::string::String;

use crate::arch::x86_64::uefi::constants::MAX_VARIABLE_NAME_LENGTH;
use crate::arch::x86_64::uefi::types::Guid;
use super::utils::ucs2_to_string;

pub struct VariableIterator {
    current_name: [u16; MAX_VARIABLE_NAME_LENGTH],
    current_guid: Guid,
    finished: bool,
}

impl VariableIterator {
    pub fn new() -> Self {
        Self {
            current_name: [0u16; MAX_VARIABLE_NAME_LENGTH],
            current_guid: Guid::null(),
            finished: false,
        }
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    pub fn current_name_ucs2(&self) -> &[u16; MAX_VARIABLE_NAME_LENGTH] {
        &self.current_name
    }

    pub fn current_name_ucs2_mut(&mut self) -> &mut [u16; MAX_VARIABLE_NAME_LENGTH] {
        &mut self.current_name
    }

    pub fn current_guid(&self) -> &Guid {
        &self.current_guid
    }

    pub fn current_guid_mut(&mut self) -> &mut Guid {
        &mut self.current_guid
    }

    pub fn set_finished(&mut self) {
        self.finished = true;
    }

    pub fn current_name_string(&self) -> String {
        ucs2_to_string(&self.current_name)
    }
}

impl Default for VariableIterator {
    fn default() -> Self {
        Self::new()
    }
}
