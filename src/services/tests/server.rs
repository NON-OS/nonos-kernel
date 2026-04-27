// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::services::server::ServerError;
use crate::test::framework::TestResult;

pub(crate) fn test_server_error_registration_failed() -> TestResult {
    let err = ServerError::RegistrationFailed;
    if err != ServerError::RegistrationFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_bind_failed() -> TestResult {
    let err = ServerError::BindFailed;
    if err != ServerError::BindFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_already_running() -> TestResult {
    let err = ServerError::AlreadyRunning;
    if err != ServerError::AlreadyRunning {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_equality() -> TestResult {
    if ServerError::RegistrationFailed != ServerError::RegistrationFailed {
        return TestResult::Fail;
    }
    if ServerError::RegistrationFailed == ServerError::BindFailed {
        return TestResult::Fail;
    }
    if ServerError::BindFailed == ServerError::AlreadyRunning {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_clone() -> TestResult {
    let err1 = ServerError::BindFailed;
    let err2 = err1.clone();
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_copy() -> TestResult {
    let err1 = ServerError::AlreadyRunning;
    let err2 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_debug_registration_failed() -> TestResult {
    let err = ServerError::RegistrationFailed;
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("RegistrationFailed") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_debug_bind_failed() -> TestResult {
    let err = ServerError::BindFailed;
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("BindFailed") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_debug_already_running() -> TestResult {
    let err = ServerError::AlreadyRunning;
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("AlreadyRunning") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_all_variants() -> TestResult {
    let errors =
        [ServerError::RegistrationFailed, ServerError::BindFailed, ServerError::AlreadyRunning];
    if errors.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_all_unique() -> TestResult {
    let errors =
        [ServerError::RegistrationFailed, ServerError::BindFailed, ServerError::AlreadyRunning];
    for i in 0..errors.len() {
        for j in (i + 1)..errors.len() {
            if errors[i] == errors[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_size() -> TestResult {
    if core::mem::size_of::<ServerError>() > 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_from_registration() -> TestResult {
    fn make_reg_error() -> ServerError {
        ServerError::RegistrationFailed
    }
    let err = make_reg_error();
    if err != ServerError::RegistrationFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_from_bind() -> TestResult {
    fn make_bind_error() -> ServerError {
        ServerError::BindFailed
    }
    let err = make_bind_error();
    if err != ServerError::BindFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_from_already_running() -> TestResult {
    fn make_running_error() -> ServerError {
        ServerError::AlreadyRunning
    }
    let err = make_running_error();
    if err != ServerError::AlreadyRunning {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_in_result_ok() -> TestResult {
    let result: Result<u32, ServerError> = Ok(42);
    if !result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap() != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_in_result_err_registration() -> TestResult {
    let result: Result<u32, ServerError> = Err(ServerError::RegistrationFailed);
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != ServerError::RegistrationFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_in_result_err_bind() -> TestResult {
    let result: Result<u32, ServerError> = Err(ServerError::BindFailed);
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != ServerError::BindFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_in_result_err_running() -> TestResult {
    let result: Result<u32, ServerError> = Err(ServerError::AlreadyRunning);
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != ServerError::AlreadyRunning {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_match_registration() -> TestResult {
    let err = ServerError::RegistrationFailed;
    match err {
        ServerError::RegistrationFailed => {}
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_match_bind() -> TestResult {
    let err = ServerError::BindFailed;
    match err {
        ServerError::BindFailed => {}
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_match_running() -> TestResult {
    let err = ServerError::AlreadyRunning;
    match err {
        ServerError::AlreadyRunning => {}
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_clone_all() -> TestResult {
    for err in
        [ServerError::RegistrationFailed, ServerError::BindFailed, ServerError::AlreadyRunning]
    {
        let cloned = err.clone();
        if err != cloned {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_copy_semantics() -> TestResult {
    let err1 = ServerError::BindFailed;
    let err2 = err1;
    let err3 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    if err2 != err3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_in_vec() -> TestResult {
    let errors = alloc::vec![
        ServerError::RegistrationFailed,
        ServerError::BindFailed,
        ServerError::AlreadyRunning,
    ];
    if errors.len() != 3 {
        return TestResult::Fail;
    }
    if errors[0] != ServerError::RegistrationFailed {
        return TestResult::Fail;
    }
    if errors[1] != ServerError::BindFailed {
        return TestResult::Fail;
    }
    if errors[2] != ServerError::AlreadyRunning {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_partial_eq_reflexive() -> TestResult {
    let err = ServerError::RegistrationFailed;
    if err != err {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_partial_eq_symmetric() -> TestResult {
    let err1 = ServerError::BindFailed;
    let err2 = ServerError::BindFailed;
    if !(err1 == err2 && err2 == err1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_server_error_eq_trait() -> TestResult {
    fn requires_eq<T: Eq>(_: T) {}
    requires_eq(ServerError::AlreadyRunning);
    TestResult::Pass
}
