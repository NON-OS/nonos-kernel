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

pub fn cmd_git_help() -> String {
    String::from(
        "usage: git <command> [<args>]

Repository commands:
   init       Create an empty Git repository
   clone      Clone a repository into a new directory

Working tree commands:
   status     Show the working tree status
   add        Add file contents to the index
   commit     Record changes to the repository
   diff       Show changes between commits

Branch commands:
   branch     List, create, or delete branches
   checkout   Switch branches or restore files

Remote commands:
   remote     Manage set of tracked repositories
   push       Update remote refs
   pull       Fetch from and integrate with remote

History commands:
   log        Show commit logs",
    )
}
