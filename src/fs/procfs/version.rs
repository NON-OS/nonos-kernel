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

use alloc::format;
use alloc::string::String;

pub const NONOS_VERSION: &str = "1.0.0";
pub const NONOS_RELEASE: &str = "1.0.0-nonos";
pub const NONOS_CODENAME: &str = "Genesis";
pub const BUILD_DATE: &str = "2026-01-01";
pub const BUILD_TIME: &str = "00:00:00";
pub const COMPILER_VERSION: &str = "rustc 1.85.0";

pub fn read_version() -> String {
    format!("NONOS version {} ({}) ({})\n", NONOS_RELEASE, COMPILER_VERSION, BUILD_DATE)
}

pub fn get_kernel_version() -> &'static str {
    NONOS_VERSION
}

pub fn get_kernel_release() -> &'static str {
    NONOS_RELEASE
}

pub fn read_version_signature() -> String {
    format!("NONOS {} {} SMP\n", NONOS_RELEASE, BUILD_DATE)
}

pub fn read_os_release() -> String {
    format!(
        "NAME=\"NONOS\"\nVERSION=\"{}\"\nID=nonos\nVERSION_ID=\"{}\"\nPRETTY_NAME=\"NONOS {}\"\nHOME_URL=\"https://nonos.io\"\nBUG_REPORT_URL=\"https://github.com/nonos/nonos/issues\"\n",
        NONOS_VERSION, NONOS_VERSION, NONOS_CODENAME
    )
}
