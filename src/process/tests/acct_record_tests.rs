use crate::process::accounting::ProcessRecord;
use crate::process::acct_record::*;
use crate::test::framework::TestResult;

pub fn acct_flag_constants() -> TestResult {
    if AFORK != 0x01 {
        return TestResult::Fail;
    }
    if ASU != 0x02 {
        return TestResult::Fail;
    }
    if ACORE != 0x08 {
        return TestResult::Fail;
    }
    if AXSIG != 0x10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn acct_flags_no_overlap() -> TestResult {
    if AFORK & ASU != 0 {
        return TestResult::Fail;
    }
    if AFORK & ACORE != 0 {
        return TestResult::Fail;
    }
    if AFORK & AXSIG != 0 {
        return TestResult::Fail;
    }
    if ASU & ACORE != 0 {
        return TestResult::Fail;
    }
    if ASU & AXSIG != 0 {
        return TestResult::Fail;
    }
    if ACORE & AXSIG != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn acct_record_default() -> TestResult {
    let rec = AcctRecord::default();
    if rec.ac_flag != 0 {
        return TestResult::Fail;
    }
    if rec.ac_version != 0 {
        return TestResult::Fail;
    }
    if rec.ac_tty != 0 {
        return TestResult::Fail;
    }
    if rec.ac_exitcode != 0 {
        return TestResult::Fail;
    }
    if rec.ac_uid != 0 {
        return TestResult::Fail;
    }
    if rec.ac_gid != 0 {
        return TestResult::Fail;
    }
    if rec.ac_pid != 0 {
        return TestResult::Fail;
    }
    if rec.ac_ppid != 0 {
        return TestResult::Fail;
    }
    if rec.ac_btime != 0 {
        return TestResult::Fail;
    }
    if rec.ac_etime != 0.0 {
        return TestResult::Fail;
    }
    if rec.ac_utime != 0.0 {
        return TestResult::Fail;
    }
    if rec.ac_stime != 0.0 {
        return TestResult::Fail;
    }
    if rec.ac_mem != 0.0 {
        return TestResult::Fail;
    }
    if rec.ac_io != 0.0 {
        return TestResult::Fail;
    }
    if rec.ac_rw != 0.0 {
        return TestResult::Fail;
    }
    if rec.ac_minflt != 0.0 {
        return TestResult::Fail;
    }
    if rec.ac_majflt != 0.0 {
        return TestResult::Fail;
    }
    if rec.ac_swaps != 0.0 {
        return TestResult::Fail;
    }
    if rec.ac_comm != [0u8; 16] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn acct_record_with_values() -> TestResult {
    let rec = AcctRecord {
        ac_flag: AFORK | ASU,
        ac_version: 3,
        ac_tty: 1,
        ac_exitcode: 0,
        ac_uid: 1000,
        ac_gid: 1000,
        ac_pid: 12345,
        ac_ppid: 1,
        ac_btime: 1000000,
        ac_etime: 5.5,
        ac_utime: 2.0,
        ac_stime: 1.5,
        ac_mem: 1024.0,
        ac_io: 512.0,
        ac_rw: 256.0,
        ac_minflt: 100.0,
        ac_majflt: 10.0,
        ac_swaps: 0.0,
        ac_comm: [0u8; 16],
    };
    if rec.ac_flag != AFORK | ASU {
        return TestResult::Fail;
    }
    if rec.ac_pid != 12345 {
        return TestResult::Fail;
    }
    if rec.ac_ppid != 1 {
        return TestResult::Fail;
    }
    if rec.ac_uid != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn acct_record_clone() -> TestResult {
    let rec1 = AcctRecord { ac_pid: 999, ac_uid: 500, ..Default::default() };
    let rec2 = rec1;
    if rec1.ac_pid != rec2.ac_pid {
        return TestResult::Fail;
    }
    if rec1.ac_uid != rec2.ac_uid {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn acct_record_comm_field() -> TestResult {
    let mut rec = AcctRecord::default();
    let name = b"test_process";
    rec.ac_comm[..name.len()].copy_from_slice(name);
    if &rec.ac_comm[..12] != b"test_process" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn acct_record_flag_combinations() -> TestResult {
    let rec = AcctRecord { ac_flag: AFORK | ACORE | AXSIG, ..Default::default() };
    if rec.ac_flag & AFORK == 0 {
        return TestResult::Fail;
    }
    if rec.ac_flag & ACORE == 0 {
        return TestResult::Fail;
    }
    if rec.ac_flag & AXSIG == 0 {
        return TestResult::Fail;
    }
    if rec.ac_flag & ASU != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_record_new() -> TestResult {
    let rec = ProcessRecord::new(123, 1, "test_app");
    if rec.pid != 123 {
        return TestResult::Fail;
    }
    if rec.ppid != 1 {
        return TestResult::Fail;
    }
    if rec.name != "test_app" {
        return TestResult::Fail;
    }
    if rec.exit_code != 0 {
        return TestResult::Fail;
    }
    if rec.start_time_ms != 0 {
        return TestResult::Fail;
    }
    if rec.end_time_ms != 0 {
        return TestResult::Fail;
    }
    if rec.elapsed_ms != 0 {
        return TestResult::Fail;
    }
    if rec.peak_memory_kb != 0 {
        return TestResult::Fail;
    }
    if rec.capabilities != 0 {
        return TestResult::Fail;
    }
    if rec.signaled {
        return TestResult::Fail;
    }
    if rec.clone_flags != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_record_clone() -> TestResult {
    let rec1 = ProcessRecord::new(456, 100, "app");
    let rec2 = rec1.clone();
    if rec1.pid != rec2.pid {
        return TestResult::Fail;
    }
    if rec1.ppid != rec2.ppid {
        return TestResult::Fail;
    }
    if rec1.name != rec2.name {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_record_format_basic() -> TestResult {
    let rec = ProcessRecord {
        pid: 100,
        ppid: 1,
        name: alloc::string::String::from("myapp"),
        exit_code: 0,
        start_time_ms: 1000,
        end_time_ms: 2000,
        elapsed_ms: 1000,
        peak_memory_kb: 512,
        capabilities: 0x1234,
        signaled: false,
        clone_flags: 0,
    };
    let formatted = rec.format();
    if !formatted.contains("[100]") {
        return TestResult::Fail;
    }
    if !formatted.contains("myapp") {
        return TestResult::Fail;
    }
    if !formatted.contains("ppid=1") {
        return TestResult::Fail;
    }
    if !formatted.contains("exit=0") {
        return TestResult::Fail;
    }
    if !formatted.contains("elapsed=1000ms") {
        return TestResult::Fail;
    }
    if !formatted.contains("mem=512KB") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_record_format_signaled() -> TestResult {
    let rec = ProcessRecord {
        pid: 200,
        ppid: 1,
        name: alloc::string::String::from("signaled_app"),
        exit_code: 9,
        start_time_ms: 0,
        end_time_ms: 100,
        elapsed_ms: 100,
        peak_memory_kb: 256,
        capabilities: 0,
        signaled: true,
        clone_flags: 0,
    };
    let formatted = rec.format();
    if !formatted.contains("[SIGNALED]") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_record_format_not_signaled() -> TestResult {
    let rec = ProcessRecord {
        pid: 300,
        ppid: 1,
        name: alloc::string::String::from("normal_app"),
        exit_code: 0,
        start_time_ms: 0,
        end_time_ms: 50,
        elapsed_ms: 50,
        peak_memory_kb: 128,
        capabilities: 0,
        signaled: false,
        clone_flags: 0,
    };
    let formatted = rec.format();
    if formatted.contains("[SIGNALED]") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_record_with_capabilities() -> TestResult {
    let rec = ProcessRecord {
        pid: 400,
        ppid: 1,
        name: alloc::string::String::from("cap_app"),
        exit_code: 0,
        start_time_ms: 0,
        end_time_ms: 0,
        elapsed_ms: 0,
        peak_memory_kb: 0,
        capabilities: 0xDEAD_BEEF_CAFE_BABE,
        signaled: false,
        clone_flags: 0,
    };
    let formatted = rec.format();
    if !(formatted.contains("deadbeefcafebabe") || formatted.contains("DEADBEEFCAFEBABE")) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn process_record_with_clone_flags() -> TestResult {
    let rec = ProcessRecord {
        pid: 500,
        ppid: 1,
        name: alloc::string::String::from("clone_app"),
        exit_code: 0,
        start_time_ms: 0,
        end_time_ms: 0,
        elapsed_ms: 0,
        peak_memory_kb: 0,
        capabilities: 0,
        signaled: false,
        clone_flags: 0x100 | 0x200,
    };
    if rec.clone_flags != 0x300 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
