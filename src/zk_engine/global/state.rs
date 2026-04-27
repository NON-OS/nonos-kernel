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

use crate::zk_engine::attestation::init_attestation_manager;
use crate::zk_engine::engine::ZKEngine;
use crate::zk_engine::types::{ZKConfig, ZKError};

pub(super) static ZK_ENGINE: spin::Once<ZKEngine> = spin::Once::new();

pub fn init_zk_engine() -> Result<(), ZKError> {
    let config = ZKConfig::default();
    let engine = ZKEngine::new(config)?;
    ZK_ENGINE.call_once(|| engine);
    init_attestation_manager()?;
    crate::log::info!("ZK Engine and attestation manager initialized successfully");
    Ok(())
}

fn try_get_or_init_zk_engine() -> Option<&'static ZKEngine> {
    if let Some(engine) = ZK_ENGINE.get() {
        return Some(engine);
    }
    match init_zk_engine() {
        Ok(_) => ZK_ENGINE.get(),
        Err(e) => {
            crate::log::error!("ZK Engine auto-initialization failed: {:?}", e);
            None
        }
    }
}

pub fn get_zk_engine() -> Result<&'static ZKEngine, ZKError> {
    try_get_or_init_zk_engine().ok_or(ZKError::NotInitialized)
}

pub fn get_zk_engine_static() -> Option<&'static ZKEngine> {
    ZK_ENGINE.get()
}

pub fn is_zk_engine_initialized() -> bool {
    ZK_ENGINE.get().is_some()
}
