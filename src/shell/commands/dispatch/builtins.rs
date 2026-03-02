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

use crate::shell::commands::builtins;
use crate::shell::commands::utils::starts_with;

pub(super) fn try_dispatch_builtins(cmd: &[u8]) -> bool {
    if cmd == b"exit" || cmd == b"logout" {
        builtins::cmd_exit();
    } else if cmd == b"export" || starts_with(cmd, b"export ") {
        builtins::cmd_export(cmd);
    } else if cmd == b"unset" || starts_with(cmd, b"unset ") {
        builtins::cmd_unset(cmd);
    } else if cmd == b"alias" || starts_with(cmd, b"alias ") {
        builtins::cmd_alias(cmd);
    } else if cmd == b"unalias" || starts_with(cmd, b"unalias ") {
        builtins::cmd_unalias(cmd);
    } else if cmd == b"type" || starts_with(cmd, b"type ") {
        builtins::cmd_type(cmd);
    } else if cmd == b"which" || starts_with(cmd, b"which ") {
        builtins::cmd_which(cmd);
    } else if cmd == b"source" || starts_with(cmd, b"source ") || starts_with(cmd, b". ") {
        builtins::cmd_source(cmd);
    } else if cmd == b"test" || starts_with(cmd, b"test ") || starts_with(cmd, b"[ ") {
        builtins::cmd_test(cmd);
    } else if cmd == b"read" || starts_with(cmd, b"read ") {
        builtins::cmd_read(cmd);
    } else if cmd == b"eval" || starts_with(cmd, b"eval ") {
        builtins::cmd_eval(cmd);
    } else if cmd == b"exec" || starts_with(cmd, b"exec ") {
        builtins::cmd_exec(cmd);
    } else if cmd == b"wait" {
        builtins::cmd_wait();
    } else if cmd == b"bg" {
        builtins::cmd_bg();
    } else if cmd == b"fg" {
        builtins::cmd_fg();
    } else if cmd == b"set" || starts_with(cmd, b"set ") {
        builtins::cmd_set(cmd);
    } else if cmd == b"true" {
        builtins::cmd_true();
    } else if cmd == b"false" {
        builtins::cmd_false();
    } else if cmd == b"sleep" || starts_with(cmd, b"sleep ") {
        builtins::cmd_sleep(cmd);
    } else if cmd == b"printenv" || starts_with(cmd, b"printenv ") {
        builtins::cmd_printenv(cmd);
    } else {
        return false;
    }
    true
}
