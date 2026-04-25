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

use super::super::database::query_by_name;
use super::super::repository::find_package;
use super::output::{format_timestamp, print_line, print_line_fmt};

pub fn cmd_info(args: &[&str]) {
    if args.is_empty() {
        print_line(b"usage: npkg info <package>");
        return;
    }
    let name = args[0];
    if let Some(installed) = query_by_name(name) {
        print_line_fmt(alloc::format!("Name:         {}", installed.meta.name).as_bytes());
        print_line_fmt(
            alloc::format!("Version:      {}", installed.meta.version.to_string()).as_bytes(),
        );
        print_line_fmt(alloc::format!("Description:  {}", installed.meta.description).as_bytes());
        print_line_fmt(alloc::format!("License:      {}", installed.meta.license).as_bytes());
        print_line_fmt(
            alloc::format!("Architecture: {}", installed.meta.architecture.as_str()).as_bytes(),
        );
        print_line_fmt(
            alloc::format!("Size:         {} bytes", installed.meta.size_installed).as_bytes(),
        );
        print_line_fmt(
            alloc::format!("Install Date: {}", format_timestamp(installed.install_time)).as_bytes(),
        );
        let reason = match installed.install_reason {
            super::super::types::InstallReason::Explicit => "explicit",
            super::super::types::InstallReason::Dependency => "dependency",
            super::super::types::InstallReason::Optional => "optional dependency",
        };
        print_line_fmt(alloc::format!("Reason:       {}", reason).as_bytes());
        print_line_fmt(alloc::format!("Files:        {}", installed.files.len()).as_bytes());
    } else if let Some(pkg) = find_package(name) {
        print_line_fmt(alloc::format!("Name:         {}", pkg.meta.name).as_bytes());
        print_line_fmt(alloc::format!("Version:      {}", pkg.meta.version.to_string()).as_bytes());
        print_line_fmt(alloc::format!("Description:  {}", pkg.meta.description).as_bytes());
        print_line_fmt(alloc::format!("License:      {}", pkg.meta.license).as_bytes());
        print_line_fmt(
            alloc::format!("Architecture: {}", pkg.meta.architecture.as_str()).as_bytes(),
        );
        print_line_fmt(alloc::format!("Download:     {} bytes", pkg.meta.size_download).as_bytes());
        print_line_fmt(
            alloc::format!("Installed:    {} bytes", pkg.meta.size_installed).as_bytes(),
        );
        if !pkg.dependencies.is_empty() {
            print_line(b"Dependencies:");
            for dep in &pkg.dependencies {
                print_line_fmt(alloc::format!("  - {}", dep.name).as_bytes());
            }
        }
        print_line(b"Status:       not installed");
    } else {
        print_line_fmt(alloc::format!("package not found: {}", name).as_bytes());
    }
}
