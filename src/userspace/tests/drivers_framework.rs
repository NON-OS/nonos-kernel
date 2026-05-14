use crate::services::driver_engine::{DriverOp, DriverRequest, DriverResponse};
use crate::test::framework::TestResult;

pub(crate) fn test_driver_op_init_value() -> TestResult {
    if DriverOp::Init as u16 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_op_read_value() -> TestResult {
    if DriverOp::Read as u16 != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_op_write_value() -> TestResult {
    if DriverOp::Write as u16 != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_op_ioctl_value() -> TestResult {
    if DriverOp::Ioctl as u16 != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_op_interrupt_value() -> TestResult {
    if DriverOp::Interrupt as u16 != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_op_shutdown_value() -> TestResult {
    if DriverOp::Shutdown as u16 != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_op_debug() -> TestResult {
    let op = DriverOp::Init;
    let debug_str = alloc::format!("{:?}", op);
    if !debug_str.contains("Init") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_op_clone() -> TestResult {
    let op = DriverOp::Read;
    let cloned = op.clone();
    if op != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_op_copy() -> TestResult {
    let op = DriverOp::Write;
    let copied: DriverOp = op;
    if op != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_op_partial_eq() -> TestResult {
    if DriverOp::Init != DriverOp::Init {
        return TestResult::Fail;
    }
    if DriverOp::Init == DriverOp::Read {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_op_eq() -> TestResult {
    let op1 = DriverOp::Ioctl;
    let op2 = DriverOp::Ioctl;
    if !(op1 == op2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_request_debug() -> TestResult {
    let req = DriverRequest { op: DriverOp::Read, device_id: 1, offset: 0, data: alloc::vec![] };
    let debug_str = alloc::format!("{:?}", req);
    if !debug_str.contains("DriverRequest") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_request_clone() -> TestResult {
    let req = DriverRequest {
        op: DriverOp::Write,
        device_id: 2,
        offset: 100,
        data: alloc::vec![1, 2, 3],
    };
    let cloned = req.clone();
    if cloned.op != DriverOp::Write {
        return TestResult::Fail;
    }
    if cloned.device_id != 2 {
        return TestResult::Fail;
    }
    if cloned.offset != 100 {
        return TestResult::Fail;
    }
    if cloned.data != alloc::vec![1, 2, 3] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_request_fields() -> TestResult {
    let req = DriverRequest {
        op: DriverOp::Ioctl,
        device_id: 42,
        offset: 1024,
        data: alloc::vec![0xAB, 0xCD],
    };
    if req.op != DriverOp::Ioctl {
        return TestResult::Fail;
    }
    if req.device_id != 42 {
        return TestResult::Fail;
    }
    if req.offset != 1024 {
        return TestResult::Fail;
    }
    if req.data.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_request_empty_data() -> TestResult {
    let req = DriverRequest { op: DriverOp::Init, device_id: 0, offset: 0, data: alloc::vec![] };
    if !req.data.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_response_ok() -> TestResult {
    let resp = DriverResponse::ok(alloc::vec![1, 2, 3]);
    if resp.status != 0 {
        return TestResult::Fail;
    }
    if resp.data != alloc::vec![1, 2, 3] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_response_ok_empty() -> TestResult {
    let resp = DriverResponse::ok(alloc::vec![]);
    if resp.status != 0 {
        return TestResult::Fail;
    }
    if !resp.data.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_response_err() -> TestResult {
    let resp = DriverResponse::err(-1);
    if resp.status != -1 {
        return TestResult::Fail;
    }
    if !resp.data.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_response_err_codes() -> TestResult {
    if DriverResponse::err(-2).status != -2 {
        return TestResult::Fail;
    }
    if DriverResponse::err(-3).status != -3 {
        return TestResult::Fail;
    }
    if DriverResponse::err(-100).status != -100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_response_debug() -> TestResult {
    let resp = DriverResponse::ok(alloc::vec![0xFF]);
    let debug_str = alloc::format!("{:?}", resp);
    if !debug_str.contains("DriverResponse") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_response_clone() -> TestResult {
    let resp = DriverResponse::ok(alloc::vec![1, 2, 3, 4]);
    let cloned = resp.clone();
    if cloned.status != resp.status {
        return TestResult::Fail;
    }
    if cloned.data != resp.data {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_response_fields() -> TestResult {
    let resp = DriverResponse { status: 5, data: alloc::vec![10, 20, 30] };
    if resp.status != 5 {
        return TestResult::Fail;
    }
    if resp.data.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_op_all_variants() -> TestResult {
    let ops = [
        DriverOp::Init,
        DriverOp::Read,
        DriverOp::Write,
        DriverOp::Ioctl,
        DriverOp::Interrupt,
        DriverOp::Shutdown,
    ];
    if ops.len() != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_op_consecutive_values() -> TestResult {
    if DriverOp::Init as u16 + 1 != DriverOp::Read as u16 {
        return TestResult::Fail;
    }
    if DriverOp::Read as u16 + 1 != DriverOp::Write as u16 {
        return TestResult::Fail;
    }
    if DriverOp::Write as u16 + 1 != DriverOp::Ioctl as u16 {
        return TestResult::Fail;
    }
    if DriverOp::Ioctl as u16 + 1 != DriverOp::Interrupt as u16 {
        return TestResult::Fail;
    }
    if DriverOp::Interrupt as u16 + 1 != DriverOp::Shutdown as u16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
