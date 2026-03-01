// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

mod constants;
mod device;
mod driver;

pub use constants::*;
pub use device::Rtl8152Device;
pub use driver::{Rtl8152Driver, init, is_connected};
