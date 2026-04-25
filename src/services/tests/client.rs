use crate::services::client::ClientError;
use crate::test::framework::TestResult;

pub(crate) fn test_client_error_not_found_variant() -> TestResult {
    let err = ClientError::NotFound;
    if err != ClientError::NotFound {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_capability_denied_variant() -> TestResult {
    let err = ClientError::CapabilityDenied;
    if err != ClientError::CapabilityDenied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_send_failed_variant() -> TestResult {
    let err = ClientError::SendFailed;
    if err != ClientError::SendFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_recv_failed_variant() -> TestResult {
    let err = ClientError::RecvFailed;
    if err != ClientError::RecvFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_timeout_variant() -> TestResult {
    let err = ClientError::Timeout;
    if err != ClientError::Timeout {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_remote_error_variant() -> TestResult {
    let err = ClientError::RemoteError(-1);
    match err {
        ClientError::RemoteError(code) => {
            if code != -1 {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_remote_error_various_codes() -> TestResult {
    let err1 = ClientError::RemoteError(-403);
    let err2 = ClientError::RemoteError(-404);
    let err3 = ClientError::RemoteError(-500);
    match err1 {
        ClientError::RemoteError(c) => {
            if c != -403 {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    match err2 {
        ClientError::RemoteError(c) => {
            if c != -404 {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    match err3 {
        ClientError::RemoteError(c) => {
            if c != -500 {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_equality_simple() -> TestResult {
    if ClientError::NotFound != ClientError::NotFound {
        return TestResult::Fail;
    }
    if ClientError::CapabilityDenied != ClientError::CapabilityDenied {
        return TestResult::Fail;
    }
    if ClientError::SendFailed != ClientError::SendFailed {
        return TestResult::Fail;
    }
    if ClientError::RecvFailed != ClientError::RecvFailed {
        return TestResult::Fail;
    }
    if ClientError::Timeout != ClientError::Timeout {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_equality_remote_error() -> TestResult {
    if ClientError::RemoteError(-1) != ClientError::RemoteError(-1) {
        return TestResult::Fail;
    }
    if ClientError::RemoteError(-1) == ClientError::RemoteError(-2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_inequality() -> TestResult {
    if ClientError::NotFound == ClientError::Timeout {
        return TestResult::Fail;
    }
    if ClientError::CapabilityDenied == ClientError::SendFailed {
        return TestResult::Fail;
    }
    if ClientError::RecvFailed == ClientError::RemoteError(0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_clone() -> TestResult {
    let err = ClientError::Timeout;
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_clone_remote_error() -> TestResult {
    let err = ClientError::RemoteError(-42);
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_copy() -> TestResult {
    let err = ClientError::SendFailed;
    let copied: ClientError = err;
    if err != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_copy_remote_error() -> TestResult {
    let err = ClientError::RemoteError(-100);
    let copied: ClientError = err;
    if err != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_debug_not_found() -> TestResult {
    let err = ClientError::NotFound;
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("NotFound") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_debug_capability_denied() -> TestResult {
    let err = ClientError::CapabilityDenied;
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("CapabilityDenied") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_debug_send_failed() -> TestResult {
    let err = ClientError::SendFailed;
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("SendFailed") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_debug_recv_failed() -> TestResult {
    let err = ClientError::RecvFailed;
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("RecvFailed") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_debug_timeout() -> TestResult {
    let err = ClientError::Timeout;
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("Timeout") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_debug_remote_error() -> TestResult {
    let err = ClientError::RemoteError(-999);
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("RemoteError") {
        return TestResult::Fail;
    }
    if !debug_str.contains("-999") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_remote_error_zero() -> TestResult {
    let err = ClientError::RemoteError(0);
    match err {
        ClientError::RemoteError(code) => {
            if code != 0 {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_remote_error_positive() -> TestResult {
    let err = ClientError::RemoteError(200);
    match err {
        ClientError::RemoteError(code) => {
            if code != 200 {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_remote_error_min() -> TestResult {
    let err = ClientError::RemoteError(i32::MIN);
    match err {
        ClientError::RemoteError(code) => {
            if code != i32::MIN {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_remote_error_max() -> TestResult {
    let err = ClientError::RemoteError(i32::MAX);
    match err {
        ClientError::RemoteError(code) => {
            if code != i32::MAX {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_all_variants_distinct() -> TestResult {
    let variants: [ClientError; 6] = [
        ClientError::NotFound,
        ClientError::CapabilityDenied,
        ClientError::SendFailed,
        ClientError::RecvFailed,
        ClientError::Timeout,
        ClientError::RemoteError(0),
    ];
    for i in 0..variants.len() {
        for j in (i + 1)..variants.len() {
            if variants[i] == variants[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_service_client_connect_nonexistent() -> TestResult {
    let result = crate::services::ServiceClient::connect("nonexistent_service_abc123");
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_client_connect_empty_name() -> TestResult {
    let result = crate::services::ServiceClient::connect("");
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_client_connect_returns_not_found_for_unknown() -> TestResult {
    let result = crate::services::ServiceClient::connect("unknown_xyz_789");
    match result {
        Err(ClientError::NotFound) => {}
        Err(_) => return TestResult::Fail,
        Ok(_) => return TestResult::Fail,
    }
    TestResult::Pass
}
