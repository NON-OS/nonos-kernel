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

mod analysis;
mod approval;
mod policy;
mod stats;
mod validation;

pub use analysis::{
    audit_device, device_security_level, is_dma_capable, is_security_relevant,
    prepare_device_for_dma, validate_device_for_driver, DeviceAuditInfo, SecurityLevel,
};
pub use approval::{
    add_to_allowlist, add_to_blocklist, approve_bus_master, check_device_allowed,
    clear_allowlist, clear_blocklist, clear_bus_master_approvals, is_bus_master_approved,
    remove_from_blocklist, revoke_bus_master, set_allowlist,
};
pub use policy::{get_security_policy, set_security_policy, SecurityPolicy};
pub use stats::{get_security_stats, reset_security_stats, SecurityStats};
pub use validation::{validate_config_write, verify_bar_not_protected};
