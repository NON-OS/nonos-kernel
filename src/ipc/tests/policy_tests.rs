// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::ipc::nonos_policy::capability::IpcCapability;
use crate::ipc::nonos_policy::violation::PolicyViolation;
use crate::ipc::nonos_message::types::SecurityLevel;
use alloc::string::String;

#[test]
fn test_ipc_capability_send() {
    let cap = IpcCapability::Send;
    assert_eq!(cap.name(), "Send");
    assert_eq!(cap as u64, 1 << 0);
}

#[test]
fn test_ipc_capability_receive() {
    let cap = IpcCapability::Receive;
    assert_eq!(cap.name(), "Receive");
    assert_eq!(cap as u64, 1 << 1);
}

#[test]
fn test_ipc_capability_create_channel() {
    let cap = IpcCapability::CreateChannel;
    assert_eq!(cap.name(), "CreateChannel");
    assert_eq!(cap as u64, 1 << 2);
}

#[test]
fn test_ipc_capability_kernel_access() {
    let cap = IpcCapability::KernelAccess;
    assert_eq!(cap.name(), "KernelAccess");
    assert_eq!(cap as u64, 1 << 3);
}

#[test]
fn test_ipc_capability_allow_unsigned() {
    let cap = IpcCapability::AllowUnsigned;
    assert_eq!(cap.name(), "AllowUnsigned");
    assert_eq!(cap as u64, 1 << 4);
}

#[test]
fn test_ipc_capability_large_messages() {
    let cap = IpcCapability::LargeMessages;
    assert_eq!(cap.name(), "LargeMessages");
    assert_eq!(cap as u64, 1 << 5);
}

#[test]
fn test_ipc_capability_unlimited_rate() {
    let cap = IpcCapability::UnlimitedRate;
    assert_eq!(cap.name(), "UnlimitedRate");
    assert_eq!(cap as u64, 1 << 6);
}

#[test]
fn test_ipc_capability_network_access() {
    let cap = IpcCapability::NetworkAccess;
    assert_eq!(cap.name(), "NetworkAccess");
    assert_eq!(cap as u64, 1 << 7);
}

#[test]
fn test_ipc_capability_filesystem_access() {
    let cap = IpcCapability::FilesystemAccess;
    assert_eq!(cap.name(), "FilesystemAccess");
    assert_eq!(cap as u64, 1 << 8);
}

#[test]
fn test_ipc_capability_crypto_access() {
    let cap = IpcCapability::CryptoAccess;
    assert_eq!(cap.name(), "CryptoAccess");
    assert_eq!(cap as u64, 1 << 9);
}

#[test]
fn test_ipc_capability_security_access() {
    let cap = IpcCapability::SecurityAccess;
    assert_eq!(cap.name(), "SecurityAccess");
    assert_eq!(cap as u64, 1 << 10);
}

#[test]
fn test_ipc_capability_broadcast() {
    let cap = IpcCapability::Broadcast;
    assert_eq!(cap.name(), "Broadcast");
    assert_eq!(cap as u64, 1 << 11);
}

#[test]
fn test_ipc_capability_clone() {
    let cap = IpcCapability::Send;
    let cloned = cap.clone();
    assert_eq!(cap, cloned);
}

#[test]
fn test_ipc_capability_copy() {
    let cap = IpcCapability::Receive;
    let copied = cap;
    assert_eq!(cap, copied);
}

#[test]
fn test_ipc_capability_equality() {
    assert_eq!(IpcCapability::Send, IpcCapability::Send);
    assert_ne!(IpcCapability::Send, IpcCapability::Receive);
}

#[test]
fn test_ipc_capability_debug() {
    let cap = IpcCapability::KernelAccess;
    let debug_str = alloc::format!("{:?}", cap);
    assert!(debug_str.contains("KernelAccess"));
}

#[test]
fn test_ipc_capability_all_have_names() {
    let caps = [
        IpcCapability::Send,
        IpcCapability::Receive,
        IpcCapability::CreateChannel,
        IpcCapability::KernelAccess,
        IpcCapability::AllowUnsigned,
        IpcCapability::LargeMessages,
        IpcCapability::UnlimitedRate,
        IpcCapability::NetworkAccess,
        IpcCapability::FilesystemAccess,
        IpcCapability::CryptoAccess,
        IpcCapability::SecurityAccess,
        IpcCapability::Broadcast,
    ];
    for cap in caps {
        assert!(!cap.name().is_empty());
    }
}

#[test]
fn test_ipc_capability_unique_values() {
    let caps = [
        IpcCapability::Send,
        IpcCapability::Receive,
        IpcCapability::CreateChannel,
        IpcCapability::KernelAccess,
        IpcCapability::AllowUnsigned,
        IpcCapability::LargeMessages,
        IpcCapability::UnlimitedRate,
        IpcCapability::NetworkAccess,
        IpcCapability::FilesystemAccess,
        IpcCapability::CryptoAccess,
        IpcCapability::SecurityAccess,
        IpcCapability::Broadcast,
    ];
    let values: alloc::vec::Vec<u64> = caps.iter().map(|c| *c as u64).collect();
    for (i, v1) in values.iter().enumerate() {
        for (j, v2) in values.iter().enumerate() {
            if i != j {
                assert_ne!(v1, v2);
            }
        }
    }
}

#[test]
fn test_ipc_capability_are_powers_of_two() {
    let caps = [
        IpcCapability::Send,
        IpcCapability::Receive,
        IpcCapability::CreateChannel,
        IpcCapability::KernelAccess,
        IpcCapability::AllowUnsigned,
        IpcCapability::LargeMessages,
        IpcCapability::UnlimitedRate,
        IpcCapability::NetworkAccess,
        IpcCapability::FilesystemAccess,
        IpcCapability::CryptoAccess,
        IpcCapability::SecurityAccess,
        IpcCapability::Broadcast,
    ];
    for cap in caps {
        let val = cap as u64;
        assert!(val.is_power_of_two());
    }
}

#[test]
fn test_policy_violation_message_too_large() {
    let v = PolicyViolation::MessageTooLarge { size: 100000, limit: 65536 };
    let display = alloc::format!("{}", v);
    assert!(display.contains("100000"));
    assert!(display.contains("65536"));
}

#[test]
fn test_policy_violation_destination_blocked() {
    let v = PolicyViolation::DestinationBlocked {
        from: String::from("moduleA"),
        to: String::from("moduleB"),
    };
    let display = alloc::format!("{}", v);
    assert!(display.contains("moduleA"));
    assert!(display.contains("moduleB"));
}

#[test]
fn test_policy_violation_security_level_insufficient() {
    let v = PolicyViolation::SecurityLevelInsufficient {
        required: SecurityLevel::Encrypted,
        actual: SecurityLevel::None,
    };
    let display = alloc::format!("{}", v);
    assert!(display.contains("Encrypted"));
    assert!(display.contains("None"));
}

#[test]
fn test_policy_violation_rate_limit_exceeded() {
    let v = PolicyViolation::RateLimitExceeded {
        module: String::from("spammer"),
        limit: 1000,
    };
    let display = alloc::format!("{}", v);
    assert!(display.contains("spammer"));
    assert!(display.contains("1000"));
}

#[test]
fn test_policy_violation_missing_capability() {
    let v = PolicyViolation::MissingCapability {
        module: String::from("untrusted"),
        capability: IpcCapability::KernelAccess,
    };
    let display = alloc::format!("{}", v);
    assert!(display.contains("untrusted"));
    assert!(display.contains("KernelAccess"));
}

#[test]
fn test_policy_violation_invalid_token() {
    let v = PolicyViolation::InvalidToken {
        module: String::from("badactor"),
        reason: "expired",
    };
    let display = alloc::format!("{}", v);
    assert!(display.contains("badactor"));
    assert!(display.contains("expired"));
}

#[test]
fn test_policy_violation_channel_creation_denied() {
    let v = PolicyViolation::ChannelCreationDenied {
        from: String::from("user"),
        to: String::from("kernel"),
    };
    let display = alloc::format!("{}", v);
    assert!(display.contains("user"));
    assert!(display.contains("kernel"));
}

#[test]
fn test_policy_violation_clone() {
    let v = PolicyViolation::MessageTooLarge { size: 100, limit: 50 };
    let cloned = v.clone();
    assert_eq!(v, cloned);
}

#[test]
fn test_policy_violation_equality() {
    let v1 = PolicyViolation::MessageTooLarge { size: 100, limit: 50 };
    let v2 = PolicyViolation::MessageTooLarge { size: 100, limit: 50 };
    let v3 = PolicyViolation::MessageTooLarge { size: 200, limit: 50 };
    assert_eq!(v1, v2);
    assert_ne!(v1, v3);
}

#[test]
fn test_policy_violation_debug() {
    let v = PolicyViolation::MessageTooLarge { size: 100, limit: 50 };
    let debug_str = alloc::format!("{:?}", v);
    assert!(debug_str.contains("MessageTooLarge"));
}

#[test]
fn test_policy_violation_different_variants() {
    let v1 = PolicyViolation::MessageTooLarge { size: 100, limit: 50 };
    let v2 = PolicyViolation::DestinationBlocked {
        from: String::from("a"),
        to: String::from("b"),
    };
    assert_ne!(v1, v2);
}

#[test]
fn test_capability_combination_example() {
    let send = IpcCapability::Send as u64;
    let receive = IpcCapability::Receive as u64;
    let combined = send | receive;
    assert_eq!(combined, 0b11);
    assert!((combined & send) != 0);
    assert!((combined & receive) != 0);
}

#[test]
fn test_capability_check_example() {
    let required = IpcCapability::KernelAccess as u64;
    let granted = IpcCapability::Send as u64 | IpcCapability::Receive as u64;
    assert!((granted & required) == 0);
}

#[test]
fn test_capability_all_granted_example() {
    let required = IpcCapability::Send as u64 | IpcCapability::Receive as u64;
    let granted = IpcCapability::Send as u64 | IpcCapability::Receive as u64 | IpcCapability::CreateChannel as u64;
    assert!((granted & required) == required);
}

#[test]
fn test_security_level_in_violation() {
    let v = PolicyViolation::SecurityLevelInsufficient {
        required: SecurityLevel::Signed,
        actual: SecurityLevel::None,
    };
    if let PolicyViolation::SecurityLevelInsufficient { required, actual } = v {
        assert_eq!(required, SecurityLevel::Signed);
        assert_eq!(actual, SecurityLevel::None);
    }
}

#[test]
fn test_capability_in_violation() {
    let v = PolicyViolation::MissingCapability {
        module: String::from("test"),
        capability: IpcCapability::Broadcast,
    };
    if let PolicyViolation::MissingCapability { capability, .. } = v {
        assert_eq!(capability, IpcCapability::Broadcast);
    }
}

#[test]
fn test_policy_violation_with_empty_strings() {
    let v = PolicyViolation::DestinationBlocked {
        from: String::new(),
        to: String::new(),
    };
    let display = alloc::format!("{}", v);
    assert!(display.contains("->"));
}

#[test]
fn test_policy_violation_with_long_module_names() {
    let v = PolicyViolation::RateLimitExceeded {
        module: String::from("very_long_module_name_that_exceeds_normal_length"),
        limit: 100,
    };
    let display = alloc::format!("{}", v);
    assert!(display.contains("very_long_module_name"));
}

