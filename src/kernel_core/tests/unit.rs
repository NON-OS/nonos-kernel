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

extern crate alloc;

use crate::kernel_core::service::{get_service, register_service, update_state, ServiceState};
use alloc::string::String;

#[test]
pub(crate) fn test_service_registry_creation() {
    let id = register_service(String::from("test_svc"), 0x1);
    let svc = get_service(id);
    assert!(svc.is_some());
    let desc = svc.unwrap();
    assert_eq!(desc.name, "test_svc");
    assert_eq!(desc.required_caps, 0x1);
}

#[test]
pub(crate) fn test_service_state_transition() {
    let id = register_service(String::from("trans_svc"), 0);
    update_state(id, ServiceState::Starting);
    let s1 = get_service(id).unwrap();
    assert_eq!(s1.state, ServiceState::Starting);
    update_state(id, ServiceState::Running);
    let s2 = get_service(id).unwrap();
    assert_eq!(s2.state, ServiceState::Running);
}
