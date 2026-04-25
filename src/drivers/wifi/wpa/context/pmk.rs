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

use super::super::super::error::WifiError;
use super::super::super::scan::SecurityType;
use super::super::crypto::pbkdf2_sha1;
use super::super::sae::sae_derive_pwd_seed;
use super::types::WpaContext;

impl WpaContext {
    pub fn derive_pmk(&mut self, password: &str, ssid: &str) -> Result<(), WifiError> {
        match self.security {
            SecurityType::Wpa2Psk | SecurityType::WpaPsk => {
                pbkdf2_sha1(password.as_bytes(), ssid.as_bytes(), 4096, &mut self.pmk)?;
                Ok(())
            }
            SecurityType::Wpa3Sae => self.derive_pmk_sae(password, ssid),
            SecurityType::Open => Ok(()),
            SecurityType::Wep | SecurityType::Enterprise | SecurityType::Unknown => {
                Err(WifiError::UnsupportedSecurity)
            }
        }
    }

    pub(super) fn derive_pmk_sae(&mut self, password: &str, _ssid: &str) -> Result<(), WifiError> {
        let pwd_seed = sae_derive_pwd_seed(password.as_bytes(), &self.aa, &self.spa);
        self.pmk.copy_from_slice(&pwd_seed);
        Ok(())
    }
}
