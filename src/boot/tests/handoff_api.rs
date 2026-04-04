use crate::boot::handoff::api::HandoffError;
use crate::boot::handoff::types::HANDOFF_VERSION;

#[test]
fn handoff_error_null_pointer_str() {
    let err = HandoffError::NullPointer;
    assert_eq!(err.as_str(), "Null handoff pointer");
}

#[test]
fn handoff_error_invalid_magic_str() {
    let err = HandoffError::InvalidMagic;
    assert_eq!(err.as_str(), "Invalid handoff magic value");
}

#[test]
fn handoff_error_version_mismatch_str() {
    let err = HandoffError::VersionMismatch { expected: 1, got: 2 };
    assert_eq!(err.as_str(), "Handoff version mismatch");
}

#[test]
fn handoff_error_size_mismatch_str() {
    let err = HandoffError::SizeMismatch { expected: 256, got: 128 };
    assert_eq!(err.as_str(), "Handoff size mismatch");
}

#[test]
fn handoff_error_already_initialized_str() {
    let err = HandoffError::AlreadyInitialized;
    assert_eq!(err.as_str(), "Handoff already initialized");
}

#[test]
fn handoff_error_invalid_data_str() {
    let err = HandoffError::InvalidData;
    assert_eq!(err.as_str(), "Invalid handoff data");
}

#[test]
fn handoff_error_display_null_pointer() {
    use alloc::string::ToString;
    let err = HandoffError::NullPointer;
    assert_eq!(err.to_string(), "Null handoff pointer");
}

#[test]
fn handoff_error_display_invalid_magic() {
    use alloc::string::ToString;
    let err = HandoffError::InvalidMagic;
    assert_eq!(err.to_string(), "Invalid handoff magic value");
}

#[test]
fn handoff_error_display_version_mismatch() {
    use alloc::string::ToString;
    let err = HandoffError::VersionMismatch { expected: 1, got: 2 };
    assert_eq!(err.to_string(), "Handoff version mismatch: expected 1, got 2");
}

#[test]
fn handoff_error_display_size_mismatch() {
    use alloc::string::ToString;
    let err = HandoffError::SizeMismatch { expected: 256, got: 128 };
    assert_eq!(err.to_string(), "Handoff size mismatch: expected 256, got 128");
}

#[test]
fn handoff_error_display_already_initialized() {
    use alloc::string::ToString;
    let err = HandoffError::AlreadyInitialized;
    assert_eq!(err.to_string(), "Handoff already initialized");
}

#[test]
fn handoff_error_display_invalid_data() {
    use alloc::string::ToString;
    let err = HandoffError::InvalidData;
    assert_eq!(err.to_string(), "Invalid handoff data");
}

#[test]
fn handoff_error_equality() {
    assert_eq!(HandoffError::NullPointer, HandoffError::NullPointer);
    assert_eq!(HandoffError::InvalidMagic, HandoffError::InvalidMagic);
    assert_eq!(HandoffError::AlreadyInitialized, HandoffError::AlreadyInitialized);
    assert_eq!(HandoffError::InvalidData, HandoffError::InvalidData);

    assert_eq!(
        HandoffError::VersionMismatch { expected: 1, got: 2 },
        HandoffError::VersionMismatch { expected: 1, got: 2 }
    );
    assert_ne!(
        HandoffError::VersionMismatch { expected: 1, got: 2 },
        HandoffError::VersionMismatch { expected: 1, got: 3 }
    );

    assert_eq!(
        HandoffError::SizeMismatch { expected: 256, got: 128 },
        HandoffError::SizeMismatch { expected: 256, got: 128 }
    );
    assert_ne!(
        HandoffError::SizeMismatch { expected: 256, got: 128 },
        HandoffError::SizeMismatch { expected: 256, got: 64 }
    );
}

#[test]
fn handoff_error_not_equal_different_variants() {
    assert_ne!(HandoffError::NullPointer, HandoffError::InvalidMagic);
    assert_ne!(HandoffError::InvalidMagic, HandoffError::AlreadyInitialized);
    assert_ne!(HandoffError::AlreadyInitialized, HandoffError::InvalidData);
}

#[test]
fn handoff_error_clone() {
    let err = HandoffError::VersionMismatch { expected: 1, got: 2 };
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn handoff_error_copy() {
    let err = HandoffError::NullPointer;
    let copied = err;
    assert_eq!(err, copied);
}

#[test]
fn handoff_error_debug() {
    use alloc::format;

    let debug = format!("{:?}", HandoffError::NullPointer);
    assert_eq!(debug, "NullPointer");

    let debug = format!("{:?}", HandoffError::InvalidMagic);
    assert_eq!(debug, "InvalidMagic");

    let debug = format!("{:?}", HandoffError::VersionMismatch { expected: 1, got: 2 });
    assert!(debug.contains("VersionMismatch"));
    assert!(debug.contains("expected: 1"));
    assert!(debug.contains("got: 2"));

    let debug = format!("{:?}", HandoffError::SizeMismatch { expected: 256, got: 128 });
    assert!(debug.contains("SizeMismatch"));

    let debug = format!("{:?}", HandoffError::AlreadyInitialized);
    assert_eq!(debug, "AlreadyInitialized");

    let debug = format!("{:?}", HandoffError::InvalidData);
    assert_eq!(debug, "InvalidData");
}

#[test]
fn handoff_version_current() {
    assert_eq!(HANDOFF_VERSION, 1);
}
