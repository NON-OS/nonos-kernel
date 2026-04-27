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
mod demo;
mod install;
mod queries;
mod state;
mod types;
mod utils;
mod wallet;

pub use constants::{GAS_PRICE_GWEI, MAINNET_CHAIN_ID, MICRO_FEE_NOX};

pub use types::{
    CapsuleCategory, CapsuleMetadata, CapsuleStore, InstallState, InstallationTask,
    InstalledCapsule,
};

pub use state::init;

pub use wallet::{get_wallet_address, set_wallet};

pub use queries::{capsule_count, get_capsule, is_installed, list_available, list_installed};

pub use install::{
    complete_install, confirm_payment, create_payment_tx, get_install_status, register_capsule,
    request_install, uninstall,
};

pub use demo::add_demo_capsules;

pub use utils::format_nox_amount;
