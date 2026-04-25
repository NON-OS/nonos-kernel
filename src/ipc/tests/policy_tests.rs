// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::ipc::{IpcCapability, PolicyViolation, SecurityLevel};
use crate::test::framework::TestResult;
use alloc::string::String;

pub(crate) fn test_ipc_capability_send() -> TestResult {
    let cap = IpcCapability::Send;
    if cap.name() != "Send" {
        return TestResult::Fail;
    }
    if cap as u64 != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_receive() -> TestResult {
    let cap = IpcCapability::Receive;
    if cap.name() != "Receive" {
        return TestResult::Fail;
    }
    if cap as u64 != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_create_channel() -> TestResult {
    let cap = IpcCapability::CreateChannel;
    if cap.name() != "CreateChannel" {
        return TestResult::Fail;
    }
    if cap as u64 != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_kernel_access() -> TestResult {
    let cap = IpcCapability::KernelAccess;
    if cap.name() != "KernelAccess" {
        return TestResult::Fail;
    }
    if cap as u64 != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_allow_unsigned() -> TestResult {
    let cap = IpcCapability::AllowUnsigned;
    if cap.name() != "AllowUnsigned" {
        return TestResult::Fail;
    }
    if cap as u64 != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_large_messages() -> TestResult {
    let cap = IpcCapability::LargeMessages;
    if cap.name() != "LargeMessages" {
        return TestResult::Fail;
    }
    if cap as u64 != 1 << 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_unlimited_rate() -> TestResult {
    let cap = IpcCapability::UnlimitedRate;
    if cap.name() != "UnlimitedRate" {
        return TestResult::Fail;
    }
    if cap as u64 != 1 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_network_access() -> TestResult {
    let cap = IpcCapability::NetworkAccess;
    if cap.name() != "NetworkAccess" {
        return TestResult::Fail;
    }
    if cap as u64 != 1 << 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_filesystem_access() -> TestResult {
    let cap = IpcCapability::FilesystemAccess;
    if cap.name() != "FilesystemAccess" {
        return TestResult::Fail;
    }
    if cap as u64 != 1 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_crypto_access() -> TestResult {
    let cap = IpcCapability::CryptoAccess;
    if cap.name() != "CryptoAccess" {
        return TestResult::Fail;
    }
    if cap as u64 != 1 << 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_security_access() -> TestResult {
    let cap = IpcCapability::SecurityAccess;
    if cap.name() != "SecurityAccess" {
        return TestResult::Fail;
    }
    if cap as u64 != 1 << 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_broadcast() -> TestResult {
    let cap = IpcCapability::Broadcast;
    if cap.name() != "Broadcast" {
        return TestResult::Fail;
    }
    if cap as u64 != 1 << 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_clone() -> TestResult {
    let cap = IpcCapability::Send;
    let cloned = cap.clone();
    if cap != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_copy() -> TestResult {
    let cap = IpcCapability::Receive;
    let copied = cap;
    if cap != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_equality() -> TestResult {
    if IpcCapability::Send != IpcCapability::Send {
        return TestResult::Fail;
    }
    if IpcCapability::Send == IpcCapability::Receive {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_debug() -> TestResult {
    let cap = IpcCapability::KernelAccess;
    let debug_str = alloc::format!("{:?}", cap);
    if !debug_str.contains("KernelAccess") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_all_have_names() -> TestResult {
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
        if cap.name().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_unique_values() -> TestResult {
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
                if v1 == v2 {
                    return TestResult::Fail;
                }
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_capability_are_powers_of_two() -> TestResult {
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
        if !val.is_power_of_two() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_policy_violation_message_too_large() -> TestResult {
    let v = PolicyViolation::MessageTooLarge { size: 100000, limit: 65536 };
    let display = alloc::format!("{}", v);
    if !display.contains("100000") {
        return TestResult::Fail;
    }
    if !display.contains("65536") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_policy_violation_destination_blocked() -> TestResult {
    let v = PolicyViolation::DestinationBlocked {
        from: String::from("moduleA"),
        to: String::from("moduleB"),
    };
    let display = alloc::format!("{}", v);
    if !display.contains("moduleA") {
        return TestResult::Fail;
    }
    if !display.contains("moduleB") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_policy_violation_security_level_insufficient() -> TestResult {
    let v = PolicyViolation::SecurityLevelInsufficient {
        required: SecurityLevel::Encrypted,
        actual: SecurityLevel::None,
    };
    let display = alloc::format!("{}", v);
    if !display.contains("Encrypted") {
        return TestResult::Fail;
    }
    if !display.contains("None") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_policy_violation_rate_limit_exceeded() -> TestResult {
    let v = PolicyViolation::RateLimitExceeded { module: String::from("spammer"), limit: 1000 };
    let display = alloc::format!("{}", v);
    if !display.contains("spammer") {
        return TestResult::Fail;
    }
    if !display.contains("1000") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_policy_violation_missing_capability() -> TestResult {
    let v = PolicyViolation::MissingCapability {
        module: String::from("untrusted"),
        capability: IpcCapability::KernelAccess,
    };
    let display = alloc::format!("{}", v);
    if !display.contains("untrusted") {
        return TestResult::Fail;
    }
    if !display.contains("KernelAccess") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_policy_violation_invalid_token() -> TestResult {
    let v = PolicyViolation::InvalidToken { module: String::from("badactor"), reason: "expired" };
    let display = alloc::format!("{}", v);
    if !display.contains("badactor") {
        return TestResult::Fail;
    }
    if !display.contains("expired") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_policy_violation_channel_creation_denied() -> TestResult {
    let v = PolicyViolation::ChannelCreationDenied {
        from: String::from("user"),
        to: String::from("kernel"),
    };
    let display = alloc::format!("{}", v);
    if !display.contains("user") {
        return TestResult::Fail;
    }
    if !display.contains("kernel") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_policy_violation_clone() -> TestResult {
    let v = PolicyViolation::MessageTooLarge { size: 100, limit: 50 };
    let cloned = v.clone();
    if v != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_policy_violation_equality() -> TestResult {
    let v1 = PolicyViolation::MessageTooLarge { size: 100, limit: 50 };
    let v2 = PolicyViolation::MessageTooLarge { size: 100, limit: 50 };
    let v3 = PolicyViolation::MessageTooLarge { size: 200, limit: 50 };
    if v1 != v2 {
        return TestResult::Fail;
    }
    if v1 == v3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_policy_violation_debug() -> TestResult {
    let v = PolicyViolation::MessageTooLarge { size: 100, limit: 50 };
    let debug_str = alloc::format!("{:?}", v);
    if !debug_str.contains("MessageTooLarge") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_policy_violation_different_variants() -> TestResult {
    let v1 = PolicyViolation::MessageTooLarge { size: 100, limit: 50 };
    let v2 = PolicyViolation::DestinationBlocked { from: String::from("a"), to: String::from("b") };
    if v1 == v2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_combination_example() -> TestResult {
    let send = IpcCapability::Send as u64;
    let receive = IpcCapability::Receive as u64;
    let combined = send | receive;
    if combined != 0b11 {
        return TestResult::Fail;
    }
    if (combined & send) == 0 {
        return TestResult::Fail;
    }
    if (combined & receive) == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_check_example() -> TestResult {
    let required = IpcCapability::KernelAccess as u64;
    let granted = IpcCapability::Send as u64 | IpcCapability::Receive as u64;
    if (granted & required) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_all_granted_example() -> TestResult {
    let required = IpcCapability::Send as u64 | IpcCapability::Receive as u64;
    let granted = IpcCapability::Send as u64
        | IpcCapability::Receive as u64
        | IpcCapability::CreateChannel as u64;
    if (granted & required) != required {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_in_violation() -> TestResult {
    let v = PolicyViolation::SecurityLevelInsufficient {
        required: SecurityLevel::Signed,
        actual: SecurityLevel::None,
    };
    if let PolicyViolation::SecurityLevelInsufficient { required, actual } = v {
        if required != SecurityLevel::Signed {
            return TestResult::Fail;
        }
        if actual != SecurityLevel::None {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_capability_in_violation() -> TestResult {
    let v = PolicyViolation::MissingCapability {
        module: String::from("test"),
        capability: IpcCapability::Broadcast,
    };
    if let PolicyViolation::MissingCapability { capability, .. } = v {
        if capability != IpcCapability::Broadcast {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_policy_violation_with_empty_strings() -> TestResult {
    let v = PolicyViolation::DestinationBlocked { from: String::new(), to: String::new() };
    let display = alloc::format!("{}", v);
    if !display.contains("->") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_policy_violation_with_long_module_names() -> TestResult {
    let v = PolicyViolation::RateLimitExceeded {
        module: String::from("very_long_module_name_that_exceeds_normal_length"),
        limit: 100,
    };
    let display = alloc::format!("{}", v);
    if !display.contains("very_long_module_name") {
        return TestResult::Fail;
    }
    TestResult::Pass
}
