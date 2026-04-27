use crate::process::scheduler::policy_types::*;
use crate::test::framework::TestResult;

pub fn sched_policy_constants() -> TestResult {
    if SCHED_NORMAL != 0 {
        return TestResult::Fail;
    }
    if SCHED_FIFO != 1 {
        return TestResult::Fail;
    }
    if SCHED_RR != 2 {
        return TestResult::Fail;
    }
    if SCHED_BATCH != 3 {
        return TestResult::Fail;
    }
    if SCHED_IDLE != 5 {
        return TestResult::Fail;
    }
    if SCHED_DEADLINE != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_priority_range() -> TestResult {
    if SCHED_PRIORITY_MIN != 1 {
        return TestResult::Fail;
    }
    if SCHED_PRIORITY_MAX != 99 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn nice_value_range() -> TestResult {
    if NICE_MIN != -20 {
        return TestResult::Fail;
    }
    if NICE_MAX != 19 {
        return TestResult::Fail;
    }
    if NICE_DEFAULT != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_flag_constants() -> TestResult {
    if SCHED_FLAG_RESET_ON_FORK != 0x01 {
        return TestResult::Fail;
    }
    if SCHED_FLAG_RECLAIM != 0x02 {
        return TestResult::Fail;
    }
    if SCHED_FLAG_DL_OVERRUN != 0x04 {
        return TestResult::Fail;
    }
    if SCHED_FLAG_KEEP_POLICY != 0x08 {
        return TestResult::Fail;
    }
    if SCHED_FLAG_KEEP_PARAMS != 0x10 {
        return TestResult::Fail;
    }
    if SCHED_FLAG_UTIL_CLAMP_MIN != 0x20 {
        return TestResult::Fail;
    }
    if SCHED_FLAG_UTIL_CLAMP_MAX != 0x40 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn ioprio_class_constants() -> TestResult {
    if IOPRIO_CLASS_NONE != 0 {
        return TestResult::Fail;
    }
    if IOPRIO_CLASS_RT != 1 {
        return TestResult::Fail;
    }
    if IOPRIO_CLASS_BE != 2 {
        return TestResult::Fail;
    }
    if IOPRIO_CLASS_IDLE != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn ioprio_who_constants() -> TestResult {
    if IOPRIO_WHO_PROCESS != 1 {
        return TestResult::Fail;
    }
    if IOPRIO_WHO_PGRP != 2 {
        return TestResult::Fail;
    }
    if IOPRIO_WHO_USER != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn timeslice_constants() -> TestResult {
    if DEFAULT_TIMESLICE_MS != 100 {
        return TestResult::Fail;
    }
    if FIFO_TIMESLICE_MS != 0 {
        return TestResult::Fail;
    }
    if RR_TIMESLICE_MS != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_default() -> TestResult {
    let attr = SchedAttr::default();
    if attr.policy != SCHED_NORMAL {
        return TestResult::Fail;
    }
    if attr.rt_priority != 0 {
        return TestResult::Fail;
    }
    if attr.nice != NICE_DEFAULT {
        return TestResult::Fail;
    }
    if attr.cpu_affinity != 0xFFFF_FFFF_FFFF_FFFF {
        return TestResult::Fail;
    }
    if attr.flags != 0 {
        return TestResult::Fail;
    }
    if attr.timeslice != DEFAULT_TIMESLICE_MS {
        return TestResult::Fail;
    }
    if attr.runtime != 0 {
        return TestResult::Fail;
    }
    if attr.deadline != 0 {
        return TestResult::Fail;
    }
    if attr.period != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_is_realtime_fifo() -> TestResult {
    let attr = SchedAttr { policy: SCHED_FIFO, rt_priority: 50, ..Default::default() };
    if !attr.is_realtime() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_is_realtime_rr() -> TestResult {
    let attr = SchedAttr { policy: SCHED_RR, rt_priority: 50, ..Default::default() };
    if !attr.is_realtime() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_is_not_realtime() -> TestResult {
    let normal = SchedAttr { policy: SCHED_NORMAL, ..Default::default() };
    let batch = SchedAttr { policy: SCHED_BATCH, ..Default::default() };
    let idle = SchedAttr { policy: SCHED_IDLE, ..Default::default() };
    let deadline = SchedAttr { policy: SCHED_DEADLINE, ..Default::default() };
    if normal.is_realtime() {
        return TestResult::Fail;
    }
    if batch.is_realtime() {
        return TestResult::Fail;
    }
    if idle.is_realtime() {
        return TestResult::Fail;
    }
    if deadline.is_realtime() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_effective_priority_normal() -> TestResult {
    let attr = SchedAttr { policy: SCHED_NORMAL, nice: 0, ..Default::default() };
    if attr.effective_priority() != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_effective_priority_normal_with_nice() -> TestResult {
    let attr_nice_max = SchedAttr { policy: SCHED_NORMAL, nice: NICE_MAX, ..Default::default() };
    if attr_nice_max.effective_priority() != 20 - NICE_MAX {
        return TestResult::Fail;
    }

    let attr_nice_min = SchedAttr { policy: SCHED_NORMAL, nice: NICE_MIN, ..Default::default() };
    if attr_nice_min.effective_priority() != 20 - NICE_MIN {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_effective_priority_fifo() -> TestResult {
    let attr = SchedAttr { policy: SCHED_FIFO, rt_priority: 50, ..Default::default() };
    if attr.effective_priority() != 150 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_effective_priority_rr() -> TestResult {
    let attr = SchedAttr { policy: SCHED_RR, rt_priority: 99, ..Default::default() };
    if attr.effective_priority() != 199 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_effective_priority_deadline() -> TestResult {
    let attr = SchedAttr { policy: SCHED_DEADLINE, ..Default::default() };
    if attr.effective_priority() != 200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_effective_priority_idle() -> TestResult {
    let attr = SchedAttr { policy: SCHED_IDLE, ..Default::default() };
    if attr.effective_priority() != -1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_effective_priority_batch() -> TestResult {
    let attr = SchedAttr { policy: SCHED_BATCH, nice: 0, ..Default::default() };
    if attr.effective_priority() != 19 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_can_run_on_cpu() -> TestResult {
    let attr = SchedAttr { cpu_affinity: 0b1010, ..Default::default() };
    if attr.can_run_on_cpu(0) {
        return TestResult::Fail;
    }
    if !attr.can_run_on_cpu(1) {
        return TestResult::Fail;
    }
    if attr.can_run_on_cpu(2) {
        return TestResult::Fail;
    }
    if !attr.can_run_on_cpu(3) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_can_run_on_cpu_high_cpu() -> TestResult {
    let attr = SchedAttr { cpu_affinity: u64::MAX, ..Default::default() };
    if attr.can_run_on_cpu(64) {
        return TestResult::Fail;
    }
    if attr.can_run_on_cpu(100) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_get_timeslice_fifo() -> TestResult {
    let attr = SchedAttr { policy: SCHED_FIFO, timeslice: 999, ..Default::default() };
    if attr.get_timeslice() != FIFO_TIMESLICE_MS {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_get_timeslice_rr() -> TestResult {
    let attr = SchedAttr { policy: SCHED_RR, timeslice: 999, ..Default::default() };
    if attr.get_timeslice() != RR_TIMESLICE_MS {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_get_timeslice_normal() -> TestResult {
    let attr = SchedAttr { policy: SCHED_NORMAL, timeslice: 50, ..Default::default() };
    if attr.get_timeslice() != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_attr_clone() -> TestResult {
    let attr1 = SchedAttr {
        policy: SCHED_FIFO,
        rt_priority: 75,
        nice: -10,
        cpu_affinity: 0xFF,
        ioprio: encode_ioprio(IOPRIO_CLASS_RT, 3),
        flags: SCHED_FLAG_RESET_ON_FORK,
        timeslice: 200,
        runtime: 1000,
        deadline: 5000,
        period: 10000,
    };
    let attr2 = attr1.clone();
    if attr1.policy != attr2.policy {
        return TestResult::Fail;
    }
    if attr1.rt_priority != attr2.rt_priority {
        return TestResult::Fail;
    }
    if attr1.nice != attr2.nice {
        return TestResult::Fail;
    }
    if attr1.cpu_affinity != attr2.cpu_affinity {
        return TestResult::Fail;
    }
    if attr1.ioprio != attr2.ioprio {
        return TestResult::Fail;
    }
    if attr1.flags != attr2.flags {
        return TestResult::Fail;
    }
    if attr1.runtime != attr2.runtime {
        return TestResult::Fail;
    }
    if attr1.deadline != attr2.deadline {
        return TestResult::Fail;
    }
    if attr1.period != attr2.period {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn encode_decode_ioprio() -> TestResult {
    let encoded = encode_ioprio(IOPRIO_CLASS_BE, 4);
    if decode_ioprio_class(encoded) != IOPRIO_CLASS_BE {
        return TestResult::Fail;
    }
    if decode_ioprio_level(encoded) != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn encode_decode_ioprio_rt() -> TestResult {
    let encoded = encode_ioprio(IOPRIO_CLASS_RT, 0);
    if decode_ioprio_class(encoded) != IOPRIO_CLASS_RT {
        return TestResult::Fail;
    }
    if decode_ioprio_level(encoded) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn encode_decode_ioprio_idle() -> TestResult {
    let encoded = encode_ioprio(IOPRIO_CLASS_IDLE, 0);
    if decode_ioprio_class(encoded) != IOPRIO_CLASS_IDLE {
        return TestResult::Fail;
    }
    if decode_ioprio_level(encoded) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn encode_ioprio_max_level() -> TestResult {
    let encoded = encode_ioprio(IOPRIO_CLASS_BE, 7);
    if decode_ioprio_class(encoded) != IOPRIO_CLASS_BE {
        return TestResult::Fail;
    }
    if decode_ioprio_level(encoded) != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_param_default() -> TestResult {
    let param = SchedParam::default();
    if param.sched_priority != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_param_with_priority() -> TestResult {
    let param = SchedParam { sched_priority: 50 };
    if param.sched_priority != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn linux_sched_attr_default() -> TestResult {
    let attr = LinuxSchedAttr::default();
    if attr.size != core::mem::size_of::<LinuxSchedAttr>() as u32 {
        return TestResult::Fail;
    }
    if attr.sched_policy != SCHED_NORMAL as u32 {
        return TestResult::Fail;
    }
    if attr.sched_flags != 0 {
        return TestResult::Fail;
    }
    if attr.sched_nice != 0 {
        return TestResult::Fail;
    }
    if attr.sched_priority != 0 {
        return TestResult::Fail;
    }
    if attr.sched_runtime != 0 {
        return TestResult::Fail;
    }
    if attr.sched_deadline != 0 {
        return TestResult::Fail;
    }
    if attr.sched_period != 0 {
        return TestResult::Fail;
    }
    if attr.sched_util_min != 0 {
        return TestResult::Fail;
    }
    if attr.sched_util_max != 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn linux_sched_attr_clone() -> TestResult {
    let attr1 = LinuxSchedAttr {
        size: 56,
        sched_policy: SCHED_DEADLINE as u32,
        sched_flags: 0x07,
        sched_nice: 0,
        sched_priority: 0,
        sched_runtime: 10_000,
        sched_deadline: 30_000,
        sched_period: 100_000,
        sched_util_min: 100,
        sched_util_max: 800,
    };
    let attr2 = attr1;
    if attr1.sched_policy != attr2.sched_policy {
        return TestResult::Fail;
    }
    if attr1.sched_runtime != attr2.sched_runtime {
        return TestResult::Fail;
    }
    if attr1.sched_deadline != attr2.sched_deadline {
        return TestResult::Fail;
    }
    if attr1.sched_period != attr2.sched_period {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_policy_stats_default() -> TestResult {
    let stats = SchedPolicyStats::default();
    if stats.total_processes != 0 {
        return TestResult::Fail;
    }
    if stats.normal_count != 0 {
        return TestResult::Fail;
    }
    if stats.fifo_count != 0 {
        return TestResult::Fail;
    }
    if stats.rr_count != 0 {
        return TestResult::Fail;
    }
    if stats.batch_count != 0 {
        return TestResult::Fail;
    }
    if stats.idle_count != 0 {
        return TestResult::Fail;
    }
    if stats.deadline_count != 0 {
        return TestResult::Fail;
    }
    if stats.policy_changes != 0 {
        return TestResult::Fail;
    }
    if stats.affinity_changes != 0 {
        return TestResult::Fail;
    }
    if stats.priority_changes != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn sched_policy_stats_clone() -> TestResult {
    let stats1 = SchedPolicyStats {
        total_processes: 100,
        normal_count: 50,
        fifo_count: 10,
        rr_count: 20,
        batch_count: 5,
        idle_count: 10,
        deadline_count: 5,
        policy_changes: 1000,
        affinity_changes: 500,
        priority_changes: 200,
    };
    let stats2 = stats1.clone();
    if stats1.total_processes != stats2.total_processes {
        return TestResult::Fail;
    }
    if stats1.normal_count != stats2.normal_count {
        return TestResult::Fail;
    }
    if stats1.policy_changes != stats2.policy_changes {
        return TestResult::Fail;
    }
    TestResult::Pass
}
