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
#[repr(u8)]
pub enum AppType {
    System = 0,
    Utility = 1,
    Browser = 2,
    Wallet = 3,
    Finance = 4,
    Privacy = 5,
    Network = 6,
    Editor = 7,
    Terminal = 8,
    Settings = 9,
    Ecosystem = 10,
}

impl AppType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "System",
            Self::Utility => "Utility",
            Self::Browser => "Browser",
            Self::Wallet => "Wallet",
            Self::Finance => "Finance",
            Self::Privacy => "Privacy",
            Self::Network => "Network",
            Self::Editor => "Editor",
            Self::Terminal => "Terminal",
            Self::Settings => "Settings",
            Self::Ecosystem => "Ecosystem",
        }
    }

    pub const fn icon(self) -> &'static str {
        match self {
            Self::System => "gear",
            Self::Utility => "tool",
            Self::Browser => "globe",
            Self::Wallet => "wallet",
            Self::Finance => "chart",
            Self::Privacy => "shield",
            Self::Network => "network",
            Self::Editor => "edit",
            Self::Terminal => "terminal",
            Self::Settings => "settings",
            Self::Ecosystem => "nonos",
        }
    }

    pub const fn requires_network(self) -> bool {
        matches!(self, Self::Browser | Self::Wallet | Self::Finance | Self::Network | Self::Ecosystem)
    }

    pub const fn requires_crypto(self) -> bool {
        matches!(self, Self::Wallet | Self::Finance | Self::Privacy | Self::Ecosystem)
    }
}

impl Default for AppType {
    fn default() -> Self {
        Self::Utility
    }
}
