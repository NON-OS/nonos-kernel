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

pub mod caps;
pub mod download;
pub mod exec;
pub mod format;
pub mod lifecycle;
pub mod loader;
pub mod manifest;
pub mod metrics;
pub mod registry;
pub mod sandbox;
pub mod signing;
pub mod types;
pub mod verify;

pub use caps::*;
pub use format::*;
pub use loader::*;
pub use manifest::*;
pub use registry::*;
pub use sandbox::*;
pub use types::*;
pub use verify::*;

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
