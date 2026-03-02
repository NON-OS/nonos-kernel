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

use super::*;

#[test]
fn test_module_state_default() {
    assert_eq!(ModuleState::default(), ModuleState::Unloaded);
}

#[test]
fn test_module_state_active() {
    assert!(ModuleState::Running.is_active());
    assert!(ModuleState::Paused.is_active());
    assert!(!ModuleState::Loaded.is_active());
    assert!(!ModuleState::Stopped.is_active());
}

#[test]
fn test_module_state_can_start() {
    assert!(ModuleState::Loaded.can_start());
    assert!(ModuleState::Stopped.can_start());
    assert!(!ModuleState::Running.can_start());
}

#[test]
fn test_module_info_new() {
    let info = ModuleInfo::new(1, alloc::string::String::from("test"));
    assert_eq!(info.id, 1);
    assert_eq!(info.name, "test");
    assert_eq!(info.state, ModuleState::Unloaded);
}

#[test]
fn test_registry_error_errno() {
    assert_eq!(RegistryError::ModuleNotFound.to_errno(), -2);
    assert_eq!(RegistryError::ModuleAlreadyExists.to_errno(), -17);
    assert_eq!(RegistryError::RegistryFull.to_errno(), -12);
}
