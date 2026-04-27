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

use super::extract::{extract_command, extract_path, extract_write_params};
use super::response::{context_response, help_response};
use crate::agents::core::AgentConfig;
use alloc::vec::Vec;

pub(super) fn process_user_request(input: &[u8], _config: &AgentConfig) -> Vec<u8> {
    let query = core::str::from_utf8(input).unwrap_or("").to_lowercase();
    if query.contains("list") && (query.contains("file") || query.contains("dir")) {
        let path = extract_path(&query).unwrap_or("/ram");
        return alloc::format!("I'll list the contents.\n<tool>list_dir {}</tool>", path)
            .into_bytes();
    }
    if query.contains("read") && query.contains("file") {
        if let Some(path) = extract_path(&query) {
            return alloc::format!("Reading file.\n<tool>read_file {}</tool>", path).into_bytes();
        }
        return b"Which file? Please provide the path.".to_vec();
    }
    if query.contains("write") && query.contains("file") {
        if let Some((path, content)) = extract_write_params(&query) {
            return alloc::format!("Writing file.\n<tool>write_file {} {}</tool>", path, content)
                .into_bytes();
        }
        return b"Please specify file path and content.".to_vec();
    }
    if query.contains("run") || query.contains("execute") || query.contains("shell") {
        if let Some(cmd) = extract_command(&query) {
            return alloc::format!("Executing.\n<tool>shell {}</tool>", cmd).into_bytes();
        }
        return b"What command would you like me to run?".to_vec();
    }
    if query.contains("system") && query.contains("info") {
        return b"<tool>sysinfo</tool>".to_vec();
    }
    if query.contains("memory") {
        return b"<tool>memory</tool>".to_vec();
    }
    if query.contains("process") {
        return b"<tool>processes</tool>".to_vec();
    }
    if query.contains("uptime") {
        return b"<tool>uptime</tool>".to_vec();
    }
    if query.contains("balance") || query.contains("wallet") {
        return b"<tool>wallet_balance</tool>".to_vec();
    }
    if query.contains("help") {
        return help_response();
    }
    if query.contains("hello") || query.starts_with("hi") {
        return b"Hello! I'm your NONOS agent. How can I help?".to_vec();
    }
    if query.contains("thank") {
        return b"You're welcome!".to_vec();
    }
    context_response(&query)
}
