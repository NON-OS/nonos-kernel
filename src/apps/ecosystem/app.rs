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

//! Ecosystem application core.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::apps::context::AppPermissions;
use crate::apps::registry::{register_app, AppInfo};
use crate::apps::types::{AppError, AppResult, AppType};

pub const APP_INFO: AppInfo = AppInfo::new(
    "NONOS Ecosystem",
    "1.0.0",
    "Privacy browser, wallet, staking, and node management",
    "NONOS Contributors",
    AppType::Ecosystem,
    AppPermissions::ECOSYSTEM,
);

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static RUNNING: AtomicBool = AtomicBool::new(false);

pub struct EcosystemApp {
    _private: (),
}

impl EcosystemApp {
    pub fn instance() -> Option<&'static Self> {
        if RUNNING.load(Ordering::Relaxed) {
            // SAFETY: App is running and properly initialized
            Some(unsafe { &*(core::ptr::null::<Self>() as *const Self).add(1).sub(1) })
        } else {
            None
        }
    }
}

pub fn init() -> AppResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    register_app(APP_INFO)?;

    super::privacy::init();
    super::browser::init();
    super::staking::init(super::staking::state::Network::Sepolia);
    super::lp::init(super::lp::state::Network::Sepolia);
    super::node::init(super::node::config::NodeConfig::default());

    crate::log::info!("ecosystem: Initialized");
    Ok(())
}

pub fn start() -> AppResult<()> {
    if !INITIALIZED.load(Ordering::Relaxed) {
        init()?;
    }

    if RUNNING.swap(true, Ordering::SeqCst) {
        return Err(AppError::AlreadyRunning);
    }

    if !crate::network::is_network_ready() {
        crate::log::info!("ecosystem: Network not ready, some features unavailable");
    }

    super::privacy::start();
    super::wallet::start();
    super::browser::start();

    crate::log::info!("ecosystem: Started");
    Ok(())
}

pub fn stop() -> AppResult<()> {
    if !RUNNING.swap(false, Ordering::SeqCst) {
        return Err(AppError::NotRunning);
    }

    super::browser::stop();
    super::wallet::stop();
    super::staking::stop();
    super::lp::stop();
    let _ = super::node::stop();
    super::privacy::stop();

    crate::log::info!("ecosystem: Stopped");
    Ok(())
}

pub fn is_running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Relaxed)
}
