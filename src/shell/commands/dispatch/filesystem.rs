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

use crate::shell::commands::files::*;
use crate::shell::commands::fileops::*;
use crate::shell::commands::utils::starts_with;

pub fn try_dispatch_filesystem(cmd: &[u8]) -> bool {
    if cmd == b"ls" || cmd == b"dir" || starts_with(cmd, b"ls ") {
        cmd_ls(cmd);
    } else if cmd == b"cd" || starts_with(cmd, b"cd ") {
        cmd_cd(cmd);
    } else if cmd == b"tree" || starts_with(cmd, b"tree ") {
        cmd_tree(cmd);
    } else if cmd == b"pwd" {
        cmd_pwd();
    } else if cmd == b"whoami" {
        cmd_whoami();
    } else if cmd == b"echo" || starts_with(cmd, b"echo ") {
        cmd_echo(cmd);
    } else if cmd == b"cat" || starts_with(cmd, b"cat ") {
        cmd_cat(cmd);
    } else if cmd == b"id" {
        cmd_id();
    } else if cmd == b"env" {
        cmd_env();
    } else if cmd == b"history" {
        cmd_history();
    } else if cmd == b"mkdir" || starts_with(cmd, b"mkdir ") {
        cmd_mkdir(cmd);
    } else if cmd == b"rmdir" || starts_with(cmd, b"rmdir ") {
        cmd_rmdir(cmd);
    } else if cmd == b"rm" || starts_with(cmd, b"rm ") {
        cmd_rm(cmd);
    } else if cmd == b"touch" || starts_with(cmd, b"touch ") {
        cmd_touch(cmd);
    } else if cmd == b"cp" || starts_with(cmd, b"cp ") {
        cmd_cp(cmd);
    } else if cmd == b"mv" || starts_with(cmd, b"mv ") {
        cmd_mv(cmd);
    } else if cmd == b"chmod" || starts_with(cmd, b"chmod ") {
        cmd_chmod(cmd);
    } else if cmd == b"chown" || starts_with(cmd, b"chown ") {
        cmd_chown(cmd);
    } else if cmd == b"ln" || starts_with(cmd, b"ln ") {
        cmd_ln(cmd);
    } else if cmd == b"stat" || starts_with(cmd, b"stat ") {
        cmd_stat(cmd);
    } else if cmd == b"file" || starts_with(cmd, b"file ") {
        cmd_file(cmd);
    } else if cmd == b"head" || starts_with(cmd, b"head ") {
        cmd_head(cmd);
    } else if cmd == b"tail" || starts_with(cmd, b"tail ") {
        cmd_tail(cmd);
    } else if cmd == b"wc" || starts_with(cmd, b"wc ") {
        cmd_wc(cmd);
    } else if cmd == b"find" || starts_with(cmd, b"find ") {
        cmd_find(cmd);
    } else if cmd == b"grep" || starts_with(cmd, b"grep ") {
        cmd_grep(cmd);
    } else if cmd == b"du" || starts_with(cmd, b"du ") {
        cmd_du(cmd);
    } else if cmd == b"sort" || starts_with(cmd, b"sort ") {
        cmd_sort(cmd);
    } else if cmd == b"uniq" || starts_with(cmd, b"uniq ") {
        cmd_uniq(cmd);
    } else if cmd == b"cut" || starts_with(cmd, b"cut ") {
        cmd_cut(cmd);
    } else if cmd == b"sed" || starts_with(cmd, b"sed ") {
        cmd_sed(cmd);
    } else if cmd == b"base64" || starts_with(cmd, b"base64 ") {
        cmd_base64(cmd);
    } else if cmd == b"tee" || starts_with(cmd, b"tee ") {
        cmd_tee(cmd);
    } else if cmd == b"tr" || starts_with(cmd, b"tr ") {
        cmd_tr(cmd);
    } else if cmd == b"rev" || starts_with(cmd, b"rev ") {
        cmd_rev(cmd);
    } else if cmd == b"xxd" || starts_with(cmd, b"xxd ") {
        cmd_xxd(cmd);
    } else {
        return false;
    }
    true
}
