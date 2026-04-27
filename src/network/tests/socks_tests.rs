// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// SOCKS proxy error and type tests

use crate::network::socks::{error_message, SocksError};
use crate::test::framework::TestResult;

pub(crate) fn test_socks_error_connection_failed() -> TestResult {
    let err = SocksError::ConnectionFailed;
    if err != SocksError::ConnectionFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socks_error_auth_failed() -> TestResult {
    let err = SocksError::AuthFailed;
    if err != SocksError::AuthFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socks_error_target_unreachable() -> TestResult {
    let err = SocksError::TargetUnreachable;
    if err != SocksError::TargetUnreachable {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socks_error_timeout() -> TestResult {
    let err = SocksError::Timeout;
    if err != SocksError::Timeout {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socks_error_protocol_error() -> TestResult {
    let err = SocksError::ProtocolError;
    if err != SocksError::ProtocolError {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socks_error_send_failed() -> TestResult {
    let err = SocksError::SendFailed;
    if err != SocksError::SendFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socks_error_recv_failed() -> TestResult {
    let err = SocksError::RecvFailed;
    if err != SocksError::RecvFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socks_error_equality() -> TestResult {
    if SocksError::Timeout != SocksError::Timeout {
        return TestResult::Fail;
    }
    if SocksError::Timeout == SocksError::SendFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socks_error_clone() -> TestResult {
    let err = SocksError::AuthFailed;
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_socks_error_copy() -> TestResult {
    let err = SocksError::ProtocolError;
    let copied: SocksError = err;
    if err != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_message_connection_failed() -> TestResult {
    let msg = error_message(SocksError::ConnectionFailed);
    if msg != "Connection failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_message_auth_failed() -> TestResult {
    let msg = error_message(SocksError::AuthFailed);
    if msg != "Authentication failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_message_target_unreachable() -> TestResult {
    let msg = error_message(SocksError::TargetUnreachable);
    if msg != "Target unreachable" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_message_timeout() -> TestResult {
    let msg = error_message(SocksError::Timeout);
    if msg != "Connection timed out" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_message_protocol_error() -> TestResult {
    let msg = error_message(SocksError::ProtocolError);
    if msg != "Protocol error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_message_send_failed() -> TestResult {
    let msg = error_message(SocksError::SendFailed);
    if msg != "Send failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_message_recv_failed() -> TestResult {
    let msg = error_message(SocksError::RecvFailed);
    if msg != "Receive failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_error_variants_distinct() -> TestResult {
    let errors = [
        SocksError::ConnectionFailed,
        SocksError::AuthFailed,
        SocksError::TargetUnreachable,
        SocksError::Timeout,
        SocksError::ProtocolError,
        SocksError::SendFailed,
        SocksError::RecvFailed,
    ];
    for i in 0..errors.len() {
        for j in (i + 1)..errors.len() {
            if errors[i] == errors[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_all_error_messages_non_empty() -> TestResult {
    let errors = [
        SocksError::ConnectionFailed,
        SocksError::AuthFailed,
        SocksError::TargetUnreachable,
        SocksError::Timeout,
        SocksError::ProtocolError,
        SocksError::SendFailed,
        SocksError::RecvFailed,
    ];
    for err in &errors {
        let msg = error_message(*err);
        if msg.is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
