use crate::userspace::drivers::{DriverRequest, DriverResponse, DriverOp};

#[test]
fn test_driver_op_init_value() {
    assert_eq!(DriverOp::Init as u16, 0);
}

#[test]
fn test_driver_op_read_value() {
    assert_eq!(DriverOp::Read as u16, 1);
}

#[test]
fn test_driver_op_write_value() {
    assert_eq!(DriverOp::Write as u16, 2);
}

#[test]
fn test_driver_op_ioctl_value() {
    assert_eq!(DriverOp::Ioctl as u16, 3);
}

#[test]
fn test_driver_op_interrupt_value() {
    assert_eq!(DriverOp::Interrupt as u16, 4);
}

#[test]
fn test_driver_op_shutdown_value() {
    assert_eq!(DriverOp::Shutdown as u16, 5);
}

#[test]
fn test_driver_op_debug() {
    let op = DriverOp::Init;
    let debug_str = alloc::format!("{:?}", op);
    assert!(debug_str.contains("Init"));
}

#[test]
fn test_driver_op_clone() {
    let op = DriverOp::Read;
    let cloned = op.clone();
    assert_eq!(op, cloned);
}

#[test]
fn test_driver_op_copy() {
    let op = DriverOp::Write;
    let copied: DriverOp = op;
    assert_eq!(op, copied);
}

#[test]
fn test_driver_op_partial_eq() {
    assert_eq!(DriverOp::Init, DriverOp::Init);
    assert_ne!(DriverOp::Init, DriverOp::Read);
}

#[test]
fn test_driver_op_eq() {
    let op1 = DriverOp::Ioctl;
    let op2 = DriverOp::Ioctl;
    assert!(op1 == op2);
}

#[test]
fn test_driver_request_debug() {
    let req = DriverRequest {
        op: DriverOp::Read,
        device_id: 1,
        offset: 0,
        data: alloc::vec![],
    };
    let debug_str = alloc::format!("{:?}", req);
    assert!(debug_str.contains("DriverRequest"));
}

#[test]
fn test_driver_request_clone() {
    let req = DriverRequest {
        op: DriverOp::Write,
        device_id: 2,
        offset: 100,
        data: alloc::vec![1, 2, 3],
    };
    let cloned = req.clone();
    assert_eq!(cloned.op, DriverOp::Write);
    assert_eq!(cloned.device_id, 2);
    assert_eq!(cloned.offset, 100);
    assert_eq!(cloned.data, alloc::vec![1, 2, 3]);
}

#[test]
fn test_driver_request_fields() {
    let req = DriverRequest {
        op: DriverOp::Ioctl,
        device_id: 42,
        offset: 1024,
        data: alloc::vec![0xAB, 0xCD],
    };
    assert_eq!(req.op, DriverOp::Ioctl);
    assert_eq!(req.device_id, 42);
    assert_eq!(req.offset, 1024);
    assert_eq!(req.data.len(), 2);
}

#[test]
fn test_driver_request_empty_data() {
    let req = DriverRequest {
        op: DriverOp::Init,
        device_id: 0,
        offset: 0,
        data: alloc::vec![],
    };
    assert!(req.data.is_empty());
}

#[test]
fn test_driver_response_ok() {
    let resp = DriverResponse::ok(alloc::vec![1, 2, 3]);
    assert_eq!(resp.status, 0);
    assert_eq!(resp.data, alloc::vec![1, 2, 3]);
}

#[test]
fn test_driver_response_ok_empty() {
    let resp = DriverResponse::ok(alloc::vec![]);
    assert_eq!(resp.status, 0);
    assert!(resp.data.is_empty());
}

#[test]
fn test_driver_response_err() {
    let resp = DriverResponse::err(-1);
    assert_eq!(resp.status, -1);
    assert!(resp.data.is_empty());
}

#[test]
fn test_driver_response_err_codes() {
    assert_eq!(DriverResponse::err(-2).status, -2);
    assert_eq!(DriverResponse::err(-3).status, -3);
    assert_eq!(DriverResponse::err(-100).status, -100);
}

#[test]
fn test_driver_response_debug() {
    let resp = DriverResponse::ok(alloc::vec![0xFF]);
    let debug_str = alloc::format!("{:?}", resp);
    assert!(debug_str.contains("DriverResponse"));
}

#[test]
fn test_driver_response_clone() {
    let resp = DriverResponse::ok(alloc::vec![1, 2, 3, 4]);
    let cloned = resp.clone();
    assert_eq!(cloned.status, resp.status);
    assert_eq!(cloned.data, resp.data);
}

#[test]
fn test_driver_response_fields() {
    let resp = DriverResponse {
        status: 5,
        data: alloc::vec![10, 20, 30],
    };
    assert_eq!(resp.status, 5);
    assert_eq!(resp.data.len(), 3);
}

#[test]
fn test_driver_op_all_variants() {
    let ops = [
        DriverOp::Init,
        DriverOp::Read,
        DriverOp::Write,
        DriverOp::Ioctl,
        DriverOp::Interrupt,
        DriverOp::Shutdown,
    ];
    assert_eq!(ops.len(), 6);
}

#[test]
fn test_driver_op_consecutive_values() {
    assert_eq!(DriverOp::Init as u16 + 1, DriverOp::Read as u16);
    assert_eq!(DriverOp::Read as u16 + 1, DriverOp::Write as u16);
    assert_eq!(DriverOp::Write as u16 + 1, DriverOp::Ioctl as u16);
    assert_eq!(DriverOp::Ioctl as u16 + 1, DriverOp::Interrupt as u16);
    assert_eq!(DriverOp::Interrupt as u16 + 1, DriverOp::Shutdown as u16);
}
