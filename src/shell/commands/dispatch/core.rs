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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::COLOR_RED;

use super::builtins::try_dispatch_builtins;
use super::system::try_dispatch_system;
use super::process::try_dispatch_process;
use super::network::try_dispatch_network;
use super::filesystem::try_dispatch_filesystem;
use super::crypto::try_dispatch_crypto;
use super::apps::try_dispatch_apps;
use super::blockchain::try_dispatch_blockchain;
use super::npkg::try_dispatch_npkg;

pub(crate) fn dispatch(cmd: &[u8]) {
    if try_dispatch_builtins(cmd) {
        return;
    }
    if try_dispatch_system(cmd) {
        return;
    }
    if try_dispatch_process(cmd) {
        return;
    }
    if try_dispatch_network(cmd) {
        return;
    }
    if try_dispatch_filesystem(cmd) {
        return;
    }
    if try_dispatch_crypto(cmd) {
        return;
    }
    if try_dispatch_apps(cmd) {
        return;
    }
    if try_dispatch_blockchain(cmd) {
        return;
    }
    if try_dispatch_npkg(cmd) {
        return;
    }
    print_line(b"Command not found. Type 'help'", COLOR_RED);
}
