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

pub mod format;
pub mod manifest;
pub mod verify;
pub mod loader;
pub mod sandbox;
pub mod registry;
pub mod types;
pub mod caps;
pub mod metrics;
pub mod lifecycle;
pub mod signing;
pub mod download;
pub mod exec;

pub use format::*;
pub use manifest::*;
pub use verify::*;
pub use loader::*;
pub use sandbox::*;
pub use registry::*;
pub use types::*;
pub use caps::*;

pub fn init() {
    registry::init_registry();
    loader::init_loader();
    metrics::collector::init();
    lifecycle::hooks::init();
    signing::keys::init();
    download::cache::init();
    download::progress::init();
    crate::sys::boot_log::ok("CAPSULE", "Runtime ready");
}
