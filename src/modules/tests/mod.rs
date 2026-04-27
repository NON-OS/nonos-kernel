// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::modules::{MemoryRequirements, ModuleInfo, ModuleState, ModuleType, PrivacyPolicy};
use alloc::string::String;

#[test]
pub(crate) fn test_module_state_unloaded() {
    let state = ModuleState::Unloaded;
    assert_eq!(state.as_str(), "Unloaded");
    assert!(!state.is_active());
    assert!(!state.can_start());
    assert!(!state.can_stop());
}

#[test]
pub(crate) fn test_module_state_loading() {
    let state = ModuleState::Loading;
    assert_eq!(state.as_str(), "Loading");
    assert!(!state.is_active());
    assert!(!state.can_start());
    assert!(!state.can_stop());
}

#[test]
pub(crate) fn test_module_state_loaded() {
    let state = ModuleState::Loaded;
    assert_eq!(state.as_str(), "Loaded");
    assert!(!state.is_active());
    assert!(state.can_start());
    assert!(!state.can_stop());
}

#[test]
pub(crate) fn test_module_state_running() {
    let state = ModuleState::Running;
    assert_eq!(state.as_str(), "Running");
    assert!(state.is_active());
    assert!(!state.can_start());
    assert!(state.can_stop());
}

#[test]
pub(crate) fn test_module_state_paused() {
    let state = ModuleState::Paused;
    assert_eq!(state.as_str(), "Paused");
    assert!(state.is_active());
    assert!(state.can_start());
    assert!(state.can_stop());
}

#[test]
pub(crate) fn test_module_state_stopping() {
    let state = ModuleState::Stopping;
    assert_eq!(state.as_str(), "Stopping");
    assert!(!state.is_active());
    assert!(!state.can_start());
    assert!(!state.can_stop());
}

#[test]
pub(crate) fn test_module_state_stopped() {
    let state = ModuleState::Stopped;
    assert_eq!(state.as_str(), "Stopped");
    assert!(!state.is_active());
    assert!(state.can_start());
    assert!(!state.can_stop());
}

#[test]
pub(crate) fn test_module_state_failed() {
    let state = ModuleState::Failed;
    assert_eq!(state.as_str(), "Failed");
    assert!(!state.is_active());
    assert!(!state.can_start());
    assert!(!state.can_stop());
}

#[test]
pub(crate) fn test_module_state_default() {
    let state = ModuleState::default();
    assert_eq!(state, ModuleState::Unloaded);
}

#[test]
pub(crate) fn test_module_state_clone() {
    let state = ModuleState::Running;
    let cloned = state.clone();
    assert_eq!(state, cloned);
}

#[test]
pub(crate) fn test_module_state_copy() {
    let state = ModuleState::Loaded;
    let copied = state;
    assert_eq!(state, copied);
}

#[test]
pub(crate) fn test_module_state_equality() {
    assert_eq!(ModuleState::Running, ModuleState::Running);
    assert_ne!(ModuleState::Running, ModuleState::Stopped);
}

#[test]
pub(crate) fn test_module_state_debug() {
    let state = ModuleState::Running;
    let debug_str = alloc::format!("{:?}", state);
    assert!(debug_str.contains("Running"));
}

#[test]
pub(crate) fn test_module_info_new() {
    let info = ModuleInfo::new(1, String::from("test_module"));
    assert_eq!(info.id, 1);
    assert_eq!(info.name, "test_module");
    assert_eq!(info.state, ModuleState::Unloaded);
    assert!(info.entry_point.is_none());
    assert_eq!(info.memory_base, 0);
    assert_eq!(info.memory_size, 0);
    assert_eq!(info.load_time, 0);
    assert!(info.params.is_none());
}

#[test]
pub(crate) fn test_module_info_with_params() {
    let info =
        ModuleInfo::new(2, String::from("param_module")).with_params(String::from("key=value"));
    assert_eq!(info.params, Some(String::from("key=value")));
}

#[test]
pub(crate) fn test_module_info_is_loaded_unloaded() {
    let info = ModuleInfo::new(1, String::from("test"));
    assert!(!info.is_loaded());
}

#[test]
pub(crate) fn test_module_info_is_loaded_running() {
    let mut info = ModuleInfo::new(1, String::from("test"));
    info.state = ModuleState::Running;
    assert!(info.is_loaded());
}

#[test]
pub(crate) fn test_module_info_is_loaded_failed() {
    let mut info = ModuleInfo::new(1, String::from("test"));
    info.state = ModuleState::Failed;
    assert!(!info.is_loaded());
}

#[test]
pub(crate) fn test_module_info_is_running() {
    let mut info = ModuleInfo::new(1, String::from("test"));
    assert!(!info.is_running());
    info.state = ModuleState::Running;
    assert!(info.is_running());
}

#[test]
pub(crate) fn test_module_info_clone() {
    let info = ModuleInfo::new(3, String::from("clone_test"));
    let cloned = info.clone();
    assert_eq!(cloned.id, info.id);
    assert_eq!(cloned.name, info.name);
    assert_eq!(cloned.state, info.state);
}

#[test]
pub(crate) fn test_module_type_system() {
    let mt = ModuleType::System;
    assert_eq!(mt.as_str(), "System");
    assert_eq!(mt.as_u8(), 0);
}

#[test]
pub(crate) fn test_module_type_user() {
    let mt = ModuleType::User;
    assert_eq!(mt.as_str(), "User");
    assert_eq!(mt.as_u8(), 1);
}

#[test]
pub(crate) fn test_module_type_driver() {
    let mt = ModuleType::Driver;
    assert_eq!(mt.as_str(), "Driver");
    assert_eq!(mt.as_u8(), 2);
}

#[test]
pub(crate) fn test_module_type_service() {
    let mt = ModuleType::Service;
    assert_eq!(mt.as_str(), "Service");
    assert_eq!(mt.as_u8(), 3);
}

#[test]
pub(crate) fn test_module_type_library() {
    let mt = ModuleType::Library;
    assert_eq!(mt.as_str(), "Library");
    assert_eq!(mt.as_u8(), 4);
}

#[test]
pub(crate) fn test_module_type_default() {
    let mt = ModuleType::default();
    assert_eq!(mt, ModuleType::User);
}

#[test]
pub(crate) fn test_module_type_clone() {
    let mt = ModuleType::Driver;
    let cloned = mt.clone();
    assert_eq!(mt, cloned);
}

#[test]
pub(crate) fn test_module_type_copy() {
    let mt = ModuleType::Service;
    let copied = mt;
    assert_eq!(mt, copied);
}

#[test]
pub(crate) fn test_module_type_equality() {
    assert_eq!(ModuleType::System, ModuleType::System);
    assert_ne!(ModuleType::System, ModuleType::User);
}

#[test]
pub(crate) fn test_privacy_policy_zero_state_only() {
    let pp = PrivacyPolicy::ZeroStateOnly;
    assert_eq!(pp.as_str(), "ZeroStateOnly");
    assert!(!pp.allows_persistence());
    assert!(pp.is_ram_only());
}

#[test]
pub(crate) fn test_privacy_policy_ephemeral() {
    let pp = PrivacyPolicy::Ephemeral;
    assert_eq!(pp.as_str(), "Ephemeral");
    assert!(!pp.allows_persistence());
    assert!(pp.is_ram_only());
}

#[test]
pub(crate) fn test_privacy_policy_encrypted_persistent() {
    let pp = PrivacyPolicy::EncryptedPersistent;
    assert_eq!(pp.as_str(), "EncryptedPersistent");
    assert!(pp.allows_persistence());
    assert!(!pp.is_ram_only());
}

#[test]
pub(crate) fn test_privacy_policy_none() {
    let pp = PrivacyPolicy::None;
    assert_eq!(pp.as_str(), "None");
    assert!(!pp.allows_persistence());
    assert!(!pp.is_ram_only());
}

#[test]
pub(crate) fn test_privacy_policy_default() {
    let pp = PrivacyPolicy::default();
    assert_eq!(pp, PrivacyPolicy::ZeroStateOnly);
}

#[test]
pub(crate) fn test_privacy_policy_clone() {
    let pp = PrivacyPolicy::Ephemeral;
    let cloned = pp.clone();
    assert_eq!(pp, cloned);
}

#[test]
pub(crate) fn test_privacy_policy_copy() {
    let pp = PrivacyPolicy::EncryptedPersistent;
    let copied = pp;
    assert_eq!(pp, copied);
}

#[test]
pub(crate) fn test_memory_requirements_default() {
    let mr = MemoryRequirements::default();
    assert!(mr.min_heap > 0);
    assert!(mr.max_heap > mr.min_heap);
    assert!(mr.stack_size > 0);
    assert!(!mr.needs_dma);
}

#[test]
pub(crate) fn test_memory_requirements_clone() {
    let mr =
        MemoryRequirements { min_heap: 4096, max_heap: 65536, stack_size: 8192, needs_dma: true };
    let cloned = mr.clone();
    assert_eq!(cloned.min_heap, 4096);
    assert_eq!(cloned.max_heap, 65536);
    assert_eq!(cloned.stack_size, 8192);
    assert!(cloned.needs_dma);
}

#[test]
pub(crate) fn test_memory_requirements_copy() {
    let mr =
        MemoryRequirements { min_heap: 1024, max_heap: 2048, stack_size: 4096, needs_dma: false };
    let copied = mr;
    assert_eq!(copied.min_heap, mr.min_heap);
    assert_eq!(copied.max_heap, mr.max_heap);
}

#[test]
pub(crate) fn test_module_state_transition_loaded_to_running() {
    let loaded = ModuleState::Loaded;
    let running = ModuleState::Running;
    assert!(loaded.can_start());
    assert!(!running.can_start());
}

#[test]
pub(crate) fn test_module_state_transition_running_to_stopped() {
    let running = ModuleState::Running;
    let stopped = ModuleState::Stopped;
    assert!(running.can_stop());
    assert!(!stopped.can_stop());
}

#[test]
pub(crate) fn test_module_state_all_variants_have_str() {
    let states = [
        ModuleState::Unloaded,
        ModuleState::Loading,
        ModuleState::Loaded,
        ModuleState::Running,
        ModuleState::Paused,
        ModuleState::Stopping,
        ModuleState::Stopped,
        ModuleState::Failed,
    ];
    for state in states {
        assert!(!state.as_str().is_empty());
    }
}

#[test]
pub(crate) fn test_module_type_all_variants_have_str() {
    let types = [
        ModuleType::System,
        ModuleType::User,
        ModuleType::Driver,
        ModuleType::Service,
        ModuleType::Library,
    ];
    for mt in types {
        assert!(!mt.as_str().is_empty());
    }
}

#[test]
pub(crate) fn test_module_type_unique_u8_values() {
    let types = [
        ModuleType::System,
        ModuleType::User,
        ModuleType::Driver,
        ModuleType::Service,
        ModuleType::Library,
    ];
    let values: alloc::vec::Vec<u8> = types.iter().map(|t| t.as_u8()).collect();
    for (i, v1) in values.iter().enumerate() {
        for (j, v2) in values.iter().enumerate() {
            if i != j {
                assert_ne!(v1, v2);
            }
        }
    }
}

#[test]
pub(crate) fn test_privacy_policy_all_variants_have_str() {
    let policies = [
        PrivacyPolicy::ZeroStateOnly,
        PrivacyPolicy::Ephemeral,
        PrivacyPolicy::EncryptedPersistent,
        PrivacyPolicy::None,
    ];
    for pp in policies {
        assert!(!pp.as_str().is_empty());
    }
}
