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

use super::super::repository::search_packages;
use super::output::{print_line, print_line_fmt};

pub fn cmd_search(args: &[&str]) {
    if args.is_empty() {
        print_line(b"usage: npkg search <query>");
        return;
    }
    let query = args[0];
    let results = search_packages(query);
    if results.is_empty() {
        print_line(b"no packages found");
        return;
    }
    for pkg in results {
        let installed =
            if super::super::database::is_installed(&pkg.meta.name) { " [installed]" } else { "" };
        print_line_fmt(
            alloc::format!(
                "{} {} - {}{}",
                pkg.meta.name,
                pkg.meta.version.to_string(),
                pkg.meta.description,
                installed
            )
            .as_bytes(),
        );
    }
}
