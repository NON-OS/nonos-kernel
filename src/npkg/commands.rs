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

use alloc::string::String;
use alloc::vec::Vec;
use super::installer::{
    install_packages, remove_packages, upgrade_all, upgrade_packages,
    InstallOptions, RemoveOptions, UpgradeOptions,
};
use super::repository::{sync_all_repositories, search_packages, find_package};
use super::database::{query_installed, query_by_name, query_by_file, get_database_stats, verify_database_integrity};
use super::cache::{clear_cache, cache_stats};

pub fn cmd_install(args: &[&str]) {
    if args.is_empty() {
        print_line(b"usage: npkg install <package> [packages...]");
        return;
    }

    let mut options = InstallOptions::default();
    let mut packages = Vec::new();

    for arg in args {
        match *arg {
            "--force" | "-f" => options.force = true,
            "--no-deps" => options.no_deps = true,
            "--no-scripts" => options.no_scripts = true,
            "--download-only" | "-d" => options.download_only = true,
            "--as-dep" => options.as_dependency = true,
            "--reinstall" => options.reinstall = true,
            _ if !arg.starts_with('-') => packages.push(*arg),
            _ => {
                print_line_fmt(alloc::format!("unknown option: {}", arg).as_bytes());
                return;
            }
        }
    }

    if packages.is_empty() {
        print_line(b"no packages specified");
        return;
    }

    match install_packages(&packages, &options) {
        Ok(()) => {
            print_line(b"installation complete");
        }
        Err(e) => {
            print_line_fmt(alloc::format!("error: {}", e.message()).as_bytes());
        }
    }
}

pub fn cmd_remove(args: &[&str]) {
    if args.is_empty() {
        print_line(b"usage: npkg remove <package> [packages...]");
        return;
    }

    let mut options = RemoveOptions::default();
    let mut packages = Vec::new();

    for arg in args {
        match *arg {
            "--recursive" | "-r" => options.recursive = true,
            "--no-scripts" => options.no_scripts = true,
            "--no-config" => options.keep_config = false,
            "--purge" => options.purge = true,
            _ if !arg.starts_with('-') => packages.push(*arg),
            _ => {
                print_line_fmt(alloc::format!("unknown option: {}", arg).as_bytes());
                return;
            }
        }
    }

    if packages.is_empty() {
        print_line(b"no packages specified");
        return;
    }

    match remove_packages(&packages, &options) {
        Ok(()) => {
            print_line(b"removal complete");
        }
        Err(e) => {
            print_line_fmt(alloc::format!("error: {}", e.message()).as_bytes());
        }
    }
}

pub fn cmd_upgrade(args: &[&str]) {
    let mut options = UpgradeOptions::default();
    let mut packages = Vec::new();

    for arg in args {
        match *arg {
            "--no-deps" => options.no_deps = true,
            "--no-scripts" => options.no_scripts = true,
            "--download-only" | "-d" => options.download_only = true,
            _ if !arg.starts_with('-') => packages.push(*arg),
            _ => {
                print_line_fmt(alloc::format!("unknown option: {}", arg).as_bytes());
                return;
            }
        }
    }

    if packages.is_empty() {
        print_line(b"upgrading all packages...");
        match upgrade_all(&options) {
            Ok(count) => {
                if count == 0 {
                    print_line(b"all packages up to date");
                } else {
                    print_line_fmt(alloc::format!("upgraded {} packages", count).as_bytes());
                }
            }
            Err(e) => {
                print_line_fmt(alloc::format!("error: {}", e.message()).as_bytes());
            }
        }
    } else {
        match upgrade_packages(&packages, &options) {
            Ok(()) => {
                print_line(b"upgrade complete");
            }
            Err(e) => {
                print_line_fmt(alloc::format!("error: {}", e.message()).as_bytes());
            }
        }
    }
}

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
        let installed = if super::database::is_installed(&pkg.meta.name) {
            " [installed]"
        } else {
            ""
        };

        print_line_fmt(alloc::format!(
            "{} {} - {}{}",
            pkg.meta.name,
            pkg.meta.version.to_string(),
            pkg.meta.description,
            installed
        ).as_bytes());
    }
}

pub fn cmd_info(args: &[&str]) {
    if args.is_empty() {
        print_line(b"usage: npkg info <package>");
        return;
    }

    let name = args[0];

    if let Some(installed) = query_by_name(name) {
        print_line_fmt(alloc::format!("Name:         {}", installed.meta.name).as_bytes());
        print_line_fmt(alloc::format!("Version:      {}", installed.meta.version.to_string()).as_bytes());
        print_line_fmt(alloc::format!("Description:  {}", installed.meta.description).as_bytes());
        print_line_fmt(alloc::format!("License:      {}", installed.meta.license).as_bytes());
        print_line_fmt(alloc::format!("Architecture: {}", installed.meta.architecture.as_str()).as_bytes());
        print_line_fmt(alloc::format!("Size:         {} bytes", installed.meta.size_installed).as_bytes());
        print_line_fmt(alloc::format!("Install Date: {}", format_timestamp(installed.install_time)).as_bytes());

        let reason = match installed.install_reason {
            super::types::InstallReason::Explicit => "explicit",
            super::types::InstallReason::Dependency => "dependency",
            super::types::InstallReason::Optional => "optional dependency",
        };
        print_line_fmt(alloc::format!("Reason:       {}", reason).as_bytes());
        print_line_fmt(alloc::format!("Files:        {}", installed.files.len()).as_bytes());
    } else if let Some(pkg) = find_package(name) {
        print_line_fmt(alloc::format!("Name:         {}", pkg.meta.name).as_bytes());
        print_line_fmt(alloc::format!("Version:      {}", pkg.meta.version.to_string()).as_bytes());
        print_line_fmt(alloc::format!("Description:  {}", pkg.meta.description).as_bytes());
        print_line_fmt(alloc::format!("License:      {}", pkg.meta.license).as_bytes());
        print_line_fmt(alloc::format!("Architecture: {}", pkg.meta.architecture.as_str()).as_bytes());
        print_line_fmt(alloc::format!("Download:     {} bytes", pkg.meta.size_download).as_bytes());
        print_line_fmt(alloc::format!("Installed:    {} bytes", pkg.meta.size_installed).as_bytes());

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

pub fn cmd_list(args: &[&str]) {
    let mut show_explicit = false;
    let mut show_deps = false;
    let mut show_orphans = false;

    for arg in args {
        match *arg {
            "--explicit" | "-e" => show_explicit = true,
            "--deps" | "-d" => show_deps = true,
            "--orphans" | "-o" => show_orphans = true,
            _ => {}
        }
    }

    if show_orphans {
        let orphans = super::database::get_orphans();
        if orphans.is_empty() {
            print_line(b"no orphan packages");
        } else {
            for name in orphans {
                print_line_fmt(name.as_bytes());
            }
        }
        return;
    }

    let packages = query_installed();

    if packages.is_empty() {
        print_line(b"no packages installed");
        return;
    }

    for pkg in packages {
        let reason = match pkg.install_reason {
            super::types::InstallReason::Explicit => {
                if show_deps { continue; }
                ""
            }
            super::types::InstallReason::Dependency | super::types::InstallReason::Optional => {
                if show_explicit { continue; }
                " [dep]"
            }
        };

        print_line_fmt(alloc::format!(
            "{} {}{}",
            pkg.meta.name,
            pkg.meta.version.to_string(),
            reason
        ).as_bytes());
    }
}

pub fn cmd_sync(_args: &[&str]) {
    print_line(b"synchronizing repositories...");

    match sync_all_repositories() {
        Ok(count) => {
            print_line_fmt(alloc::format!("synchronized {} packages", count).as_bytes());
        }
        Err(e) => {
            print_line_fmt(alloc::format!("error: {}", e.message()).as_bytes());
        }
    }
}

pub fn cmd_clean(_args: &[&str]) {
    match clear_cache() {
        Ok(freed) => {
            print_line_fmt(alloc::format!("freed {} bytes", freed).as_bytes());
        }
        Err(e) => {
            print_line_fmt(alloc::format!("error: {}", e.message()).as_bytes());
        }
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
        Err(e) => {
            print_line_fmt(alloc::format!("error: {}", e.message()).as_bytes());
        }
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
        print_line_fmt(alloc::format!("  Explicit:         {}", stats.explicit_packages).as_bytes());
        print_line_fmt(alloc::format!("  Dependencies:     {}", stats.dependency_packages).as_bytes());
        print_line_fmt(alloc::format!("Total files:        {}", stats.total_files).as_bytes());
        print_line_fmt(alloc::format!("Total size:         {} bytes", stats.total_size).as_bytes());

        if let Some(cache) = cache_stats() {
            print_line_fmt(alloc::format!("Cache size:         {} bytes", cache.total_size).as_bytes());
            print_line_fmt(alloc::format!("Cached packages:    {}", cache.package_count).as_bytes());
        }
    } else {
        print_line(b"database not initialized");
    }
}

fn print_line(msg: &[u8]) {
    crate::shell::output::print_line(msg, crate::graphics::framebuffer::COLOR_WHITE);
}

fn print_line_fmt(msg: &[u8]) {
    crate::shell::output::print_line(msg, crate::graphics::framebuffer::COLOR_WHITE);
}

fn format_timestamp(ts: u64) -> String {
    let secs = ts % 60;
    let mins = (ts / 60) % 60;
    let hours = (ts / 3600) % 24;
    let days = ts / 86400;

    let years = 1970 + days / 365;
    let remaining_days = days % 365;
    let month = remaining_days / 30 + 1;
    let day = remaining_days % 30 + 1;

    alloc::format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        years, month, day, hours, mins, secs)
}
