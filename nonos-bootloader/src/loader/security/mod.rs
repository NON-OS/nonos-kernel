// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

mod audit;
mod checks;
mod policy;
pub mod security;

pub use security::{
    check_address_bounds, check_critical_memory, check_pie_policy, check_size_policy,
    check_wx_policy, compute_kernel_hash, validate_security, verify_kernel_hash, SecurityAudit,
    SecurityCheckResult, SecurityPolicy,
};
