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

mod constants;
mod types;
mod state;
mod wallet;
mod queries;
mod install;
mod demo;
mod utils;

pub use constants::{MICRO_FEE_NOX, GAS_PRICE_GWEI, MAINNET_CHAIN_ID};

pub use types::{
    CapsuleCategory, CapsuleMetadata, InstallState,
    InstallationTask, InstalledCapsule, CapsuleStore,
};

pub use state::init;

pub use wallet::{set_wallet, get_wallet_address};

pub use queries::{list_available, list_installed, get_capsule, is_installed, capsule_count};

pub use install::{
    request_install, create_payment_tx, confirm_payment,
    complete_install, uninstall, get_install_status, register_capsule,
};

pub use demo::add_demo_capsules;

pub use utils::format_nox_amount;
