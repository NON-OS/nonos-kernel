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

use crate::services::ServiceResponse;
use crate::shell;
use alloc::vec::Vec;

pub(super) fn shell_execute(seq: u32, data: &[u8]) -> ServiceResponse {
    let output = shell::execute_and_capture(data);
    ServiceResponse::ok(seq, output)
}

pub(super) fn shell_complete(seq: u32, data: &[u8]) -> ServiceResponse {
    let completer = shell::terminal::completion::get_completer();
    completer.find_completions(data);
    ServiceResponse::ok(seq, alloc::vec![completer.match_count() as u8])
}

pub(super) fn shell_history(seq: u32) -> ServiceResponse {
    let hist = shell::terminal::history::get_history();
    let mut out = Vec::new();
    for i in 0..hist.count() {
        if let Some((entry, len)) = hist.get(i) {
            out.extend_from_slice(&entry[..len]);
            out.push(0);
        }
    }
    ServiceResponse::ok(seq, out)
}
