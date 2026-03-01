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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiState {
    Uninitialized,
    HwReady,
    FwLoaded,
    Ready,
    Scanning,
    Connecting,
    Connected,
    Disconnecting,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerSaveMode {
    Disabled,
    LightSleep,
    DeepSleep,
    UltraLowPower,
}

#[derive(Debug, Clone, Copy)]
pub struct PowerConfig {
    pub mode: PowerSaveMode,
    pub listen_interval: u16,
    pub dtim_period: u8,
    pub skip_dtim: bool,
    pub rx_chain_power_save: bool,
    pub tx_power_reduction_dbm: u8,
}

impl Default for PowerConfig {
    fn default() -> Self {
        Self {
            mode: PowerSaveMode::Disabled,
            listen_interval: 10,
            dtim_period: 3,
            skip_dtim: false,
            rx_chain_power_save: true,
            tx_power_reduction_dbm: 0,
        }
    }
}
