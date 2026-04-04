// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::services::server::ServerError;

#[test]
fn test_server_error_registration_failed() {
    let err = ServerError::RegistrationFailed;
    assert_eq!(err, ServerError::RegistrationFailed);
}

#[test]
fn test_server_error_bind_failed() {
    let err = ServerError::BindFailed;
    assert_eq!(err, ServerError::BindFailed);
}

#[test]
fn test_server_error_already_running() {
    let err = ServerError::AlreadyRunning;
    assert_eq!(err, ServerError::AlreadyRunning);
}

#[test]
fn test_server_error_equality() {
    assert_eq!(ServerError::RegistrationFailed, ServerError::RegistrationFailed);
    assert_ne!(ServerError::RegistrationFailed, ServerError::BindFailed);
    assert_ne!(ServerError::BindFailed, ServerError::AlreadyRunning);
}

#[test]
fn test_server_error_clone() {
    let err1 = ServerError::BindFailed;
    let err2 = err1.clone();
    assert_eq!(err1, err2);
}

#[test]
fn test_server_error_copy() {
    let err1 = ServerError::AlreadyRunning;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_server_error_debug_registration_failed() {
    let err = ServerError::RegistrationFailed;
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("RegistrationFailed"));
}

#[test]
fn test_server_error_debug_bind_failed() {
    let err = ServerError::BindFailed;
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("BindFailed"));
}

#[test]
fn test_server_error_debug_already_running() {
    let err = ServerError::AlreadyRunning;
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("AlreadyRunning"));
}

#[test]
fn test_server_error_all_variants() {
    let errors = [
        ServerError::RegistrationFailed,
        ServerError::BindFailed,
        ServerError::AlreadyRunning,
    ];
    assert_eq!(errors.len(), 3);
}

#[test]
fn test_server_error_all_unique() {
    let errors = [
        ServerError::RegistrationFailed,
        ServerError::BindFailed,
        ServerError::AlreadyRunning,
    ];
    for i in 0..errors.len() {
        for j in (i + 1)..errors.len() {
            assert_ne!(errors[i], errors[j]);
        }
    }
}

#[test]
fn test_server_error_size() {
    assert!(core::mem::size_of::<ServerError>() <= 8);
}

#[test]
fn test_server_error_from_registration() {
    fn make_reg_error() -> ServerError { ServerError::RegistrationFailed }
    let err = make_reg_error();
    assert_eq!(err, ServerError::RegistrationFailed);
}

#[test]
fn test_server_error_from_bind() {
    fn make_bind_error() -> ServerError { ServerError::BindFailed }
    let err = make_bind_error();
    assert_eq!(err, ServerError::BindFailed);
}

#[test]
fn test_server_error_from_already_running() {
    fn make_running_error() -> ServerError { ServerError::AlreadyRunning }
    let err = make_running_error();
    assert_eq!(err, ServerError::AlreadyRunning);
}

#[test]
fn test_server_error_in_result_ok() {
    let result: Result<u32, ServerError> = Ok(42);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_server_error_in_result_err_registration() {
    let result: Result<u32, ServerError> = Err(ServerError::RegistrationFailed);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), ServerError::RegistrationFailed);
}

#[test]
fn test_server_error_in_result_err_bind() {
    let result: Result<u32, ServerError> = Err(ServerError::BindFailed);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), ServerError::BindFailed);
}

#[test]
fn test_server_error_in_result_err_running() {
    let result: Result<u32, ServerError> = Err(ServerError::AlreadyRunning);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), ServerError::AlreadyRunning);
}

#[test]
fn test_server_error_match_registration() {
    let err = ServerError::RegistrationFailed;
    match err {
        ServerError::RegistrationFailed => assert!(true),
        _ => panic!("Expected RegistrationFailed"),
    }
}

#[test]
fn test_server_error_match_bind() {
    let err = ServerError::BindFailed;
    match err {
        ServerError::BindFailed => assert!(true),
        _ => panic!("Expected BindFailed"),
    }
}

#[test]
fn test_server_error_match_running() {
    let err = ServerError::AlreadyRunning;
    match err {
        ServerError::AlreadyRunning => assert!(true),
        _ => panic!("Expected AlreadyRunning"),
    }
}

#[test]
fn test_server_error_clone_all() {
    for err in [ServerError::RegistrationFailed, ServerError::BindFailed, ServerError::AlreadyRunning] {
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }
}

#[test]
fn test_server_error_copy_semantics() {
    let err1 = ServerError::BindFailed;
    let err2 = err1;
    let err3 = err1;
    assert_eq!(err1, err2);
    assert_eq!(err2, err3);
}

#[test]
fn test_server_error_in_vec() {
    let errors = alloc::vec![
        ServerError::RegistrationFailed,
        ServerError::BindFailed,
        ServerError::AlreadyRunning,
    ];
    assert_eq!(errors.len(), 3);
    assert_eq!(errors[0], ServerError::RegistrationFailed);
    assert_eq!(errors[1], ServerError::BindFailed);
    assert_eq!(errors[2], ServerError::AlreadyRunning);
}

#[test]
fn test_server_error_partial_eq_reflexive() {
    let err = ServerError::RegistrationFailed;
    assert_eq!(err, err);
}

#[test]
fn test_server_error_partial_eq_symmetric() {
    let err1 = ServerError::BindFailed;
    let err2 = ServerError::BindFailed;
    assert!(err1 == err2 && err2 == err1);
}

#[test]
fn test_server_error_eq_trait() {
    fn requires_eq<T: Eq>(_: T) {}
    requires_eq(ServerError::AlreadyRunning);
}

