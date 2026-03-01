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

use crate::security::{hardening, crypto, boot, policy, monitoring, network, quantum, module_db};

pub fn init_all_security() -> Result<(), &'static str> {
    hardening::spectre_mitigations::init()?;
    hardening::memory_sanitization::init()?;
    crypto::constant_time::init()?;
    crypto::key_management::init().map_err(|_| "Key management init failed")?;
    boot::secure_boot::init().map_err(|_| "Secure boot init failed")?;
    policy::capability::init_capabilities()?;
    policy::advanced::init_advanced_security()?;
    monitoring::audit::init()?;
    boot::firmware::init()?;
    module_db::init()?;
    monitoring::monitor::set_enabled(true);
    crypto::random::init()?;
    monitoring::rootkit::init()?;
    crypto::trusted_hashes::init()?;
    crypto::trusted_keys::init()?;
    monitoring::leak_detection::add_sensitive_pattern("password");
    monitoring::leak_detection::add_sensitive_pattern("private_key");
    monitoring::leak_detection::add_sensitive_pattern("ssn");
    network::dns_privacy::scan_dns_queries();
    network::zkids::init_zkids()?;
    let _ = quantum::pqc::QuantumSecurityEngine::new();
    policy::session::init()?;
    Ok(())
}
