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

use super::super::cache::{cache_stats, clear_cache};
use super::super::database::{
    get_database_stats, query_by_file, query_by_name, verify_database_integrity,
};
use super::super::repository::sync_all_repositories;
use super::output::{print_line, print_line_fmt};

pub fn cmd_sync(_args: &[&str]) {
    print_line(b"synchronizing repositories...");
    match sync_all_repositories() {
        Ok(count) => print_line_fmt(alloc::format!("synchronized {} packages", count).as_bytes()),
        Err(e) => print_line_fmt(alloc::format!("error: {}", e.message()).as_bytes()),
    }
}

pub fn cmd_clean(_args: &[&str]) {
    match clear_cache() {
        Ok(freed) => print_line_fmt(alloc::format!("freed {} bytes", freed).as_bytes()),
        Err(e) => print_line_fmt(alloc::format!("error: {}", e.message()).as_bytes()),
    }
}

pub fn cmd_verify(_args: &[&str]) {
    print_line(b"verifying package database...");
    match verify_database_integrity() {
        Ok(issues) => {
            if issues.is_empty() {
                print_line(b"database integrity OK");
            } else {
                print_line_fmt(alloc::format!("found {} issues:", issues.len()).as_bytes());
                for issue in issues {
                    print_line_fmt(alloc::format!("  {}", issue).as_bytes());
                }
            }
        }
        Err(e) => print_line_fmt(alloc::format!("error: {}", e.message()).as_bytes()),
    }
}

pub fn cmd_files(args: &[&str]) {
    if args.is_empty() {
        print_line(b"usage: npkg files <package>");
        return;
    }
    let name = args[0];
    if let Some(pkg) = query_by_name(name) {
        for file in &pkg.files {
            print_line_fmt(file.as_bytes());
        }
    } else {
        print_line_fmt(alloc::format!("package not installed: {}", name).as_bytes());
    }
}

pub fn cmd_owner(args: &[&str]) {
    if args.is_empty() {
        print_line(b"usage: npkg owner <file>");
        return;
    }
    let path = args[0];
    if let Some(owner) = query_by_file(path) {
        print_line_fmt(alloc::format!("{} is owned by {}", path, owner).as_bytes());
    } else {
        print_line_fmt(alloc::format!("{} is not owned by any package", path).as_bytes());
    }
}

pub fn cmd_stats() {
    if let Some(stats) = get_database_stats() {
        print_line_fmt(alloc::format!("Installed packages: {}", stats.total_packages).as_bytes());
        print_line_fmt(
            alloc::format!("  Explicit:         {}", stats.explicit_packages).as_bytes(),
        );
        print_line_fmt(
            alloc::format!("  Dependencies:     {}", stats.dependency_packages).as_bytes(),
        );
        print_line_fmt(alloc::format!("Total files:        {}", stats.total_files).as_bytes());
        print_line_fmt(alloc::format!("Total size:         {} bytes", stats.total_size).as_bytes());
        if let Some(cache) = cache_stats() {
            print_line_fmt(
                alloc::format!("Cache size:         {} bytes", cache.total_size).as_bytes(),
            );
            print_line_fmt(
                alloc::format!("Cached packages:    {}", cache.package_count).as_bytes(),
            );
        }
    } else {
        print_line(b"database not initialized");
    }
}
