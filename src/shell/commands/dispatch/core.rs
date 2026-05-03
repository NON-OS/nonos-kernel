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

use crate::display::framebuffer::COLOR_RED;
use crate::shell::output::print_line;

use super::agents::try_dispatch_agents;
use super::apps::try_dispatch_apps;
use super::blockchain::try_dispatch_blockchain;
use super::builtins::try_dispatch_builtins;
use super::crypto::try_dispatch_crypto;
use super::devtools::try_dispatch_dev;
use super::filesystem::try_dispatch_filesystem;
use super::git::try_dispatch_git;
use super::network::try_dispatch_network;
use super::nox::try_dispatch_nox;
use super::npkg::try_dispatch_npkg;
use super::process::try_dispatch_process;
use super::script::try_dispatch_script;
use super::system::try_dispatch_system;

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
    if try_dispatch_nox(cmd) {
        return;
    }
    if try_dispatch_dev(cmd) {
        return;
    }
    if try_dispatch_agents(cmd) {
        return;
    }
    if try_dispatch_script(cmd) {
        return;
    }
    if try_dispatch_git(cmd) {
        return;
    }
    print_line(b"Command not found. Type 'help'", COLOR_RED);
}
