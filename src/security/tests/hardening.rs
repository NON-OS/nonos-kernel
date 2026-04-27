// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// CPU hardening and mitigation tests

extern crate alloc;

use crate::security::*;
use crate::test::framework::TestResult;
use alloc::format;

pub(crate) fn test_cpu_vulnerabilities_default() -> TestResult {
    let vulns = CpuVulnerabilities::default();
    if !vulns.spectre_v1 {
        return TestResult::Fail;
    }
    if !vulns.spectre_v2 {
        return TestResult::Fail;
    }
    if !vulns.spectre_v4 {
        return TestResult::Fail;
    }
    if !vulns.meltdown {
        return TestResult::Fail;
    }
    if !vulns.mds {
        return TestResult::Fail;
    }
    if !vulns.l1tf {
        return TestResult::Fail;
    }
    if !vulns.taa {
        return TestResult::Fail;
    }
    if !vulns.srbds {
        return TestResult::Fail;
    }
    if !vulns.retbleed {
        return TestResult::Fail;
    }
    if !vulns.mmio_stale_data {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_vulnerabilities_all_fields() -> TestResult {
    let vulns = CpuVulnerabilities {
        spectre_v1: false,
        spectre_v2: false,
        spectre_v4: false,
        meltdown: false,
        mds: false,
        l1tf: false,
        taa: false,
        srbds: false,
        retbleed: false,
        mmio_stale_data: false,
    };
    if vulns.spectre_v1 {
        return TestResult::Fail;
    }
    if vulns.spectre_v2 {
        return TestResult::Fail;
    }
    if vulns.meltdown {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_vulnerabilities_copy() -> TestResult {
    let vulns1 = CpuVulnerabilities::default();
    let vulns2 = vulns1;
    if vulns1.spectre_v1 != vulns2.spectre_v1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cpu_vulnerabilities_clone() -> TestResult {
    let vulns1 = CpuVulnerabilities::default();
    let vulns2 = vulns1.clone();
    if vulns1.spectre_v2 != vulns2.spectre_v2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mitigation_status_default() -> TestResult {
    let status = MitigationStatus::default();
    if status.kpti_enabled {
        return TestResult::Fail;
    }
    if !status.retpoline_enabled {
        return TestResult::Fail;
    }
    if status.ibrs_enabled {
        return TestResult::Fail;
    }
    if status.ibpb_enabled {
        return TestResult::Fail;
    }
    if status.stibp_enabled {
        return TestResult::Fail;
    }
    if status.ssbd_enabled {
        return TestResult::Fail;
    }
    if status.mds_clear_enabled {
        return TestResult::Fail;
    }
    if status.l1d_flush_enabled {
        return TestResult::Fail;
    }
    if status.taa_mitigation_enabled {
        return TestResult::Fail;
    }
    if status.rsb_stuffing_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mitigation_status_all_enabled() -> TestResult {
    let status = MitigationStatus {
        kpti_enabled: true,
        retpoline_enabled: true,
        ibrs_enabled: true,
        ibpb_enabled: true,
        stibp_enabled: true,
        ssbd_enabled: true,
        mds_clear_enabled: true,
        l1d_flush_enabled: true,
        taa_mitigation_enabled: true,
        rsb_stuffing_enabled: true,
    };
    if !status.kpti_enabled {
        return TestResult::Fail;
    }
    if !status.ibrs_enabled {
        return TestResult::Fail;
    }
    if !status.mds_clear_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mitigation_status_copy() -> TestResult {
    let status1 = MitigationStatus::default();
    let status2 = status1;
    if status1.kpti_enabled != status2.kpti_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mitigation_status_clone() -> TestResult {
    let status1 = MitigationStatus::default();
    let status2 = status1.clone();
    if status1.retpoline_enabled != status2.retpoline_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mitigation_status_partial_enabled() -> TestResult {
    let status = MitigationStatus {
        kpti_enabled: true,
        retpoline_enabled: true,
        ibrs_enabled: false,
        ibpb_enabled: true,
        stibp_enabled: false,
        ssbd_enabled: false,
        mds_clear_enabled: true,
        l1d_flush_enabled: false,
        taa_mitigation_enabled: false,
        rsb_stuffing_enabled: true,
    };
    if !status.kpti_enabled {
        return TestResult::Fail;
    }
    if status.ibrs_enabled {
        return TestResult::Fail;
    }
    if !status.mds_clear_enabled {
        return TestResult::Fail;
    }
    if !status.rsb_stuffing_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lfence_barrier() -> TestResult {
    lfence();
    TestResult::Pass
}

pub(crate) fn test_mfence_barrier() -> TestResult {
    mfence();
    TestResult::Pass
}

pub(crate) fn test_sfence_barrier() -> TestResult {
    sfence();
    TestResult::Pass
}

pub(crate) fn test_array_index_mask_nospec() -> TestResult {
    let mask = array_index_mask_nospec(5, 10);
    if mask != !0usize {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_array_index_mask_nospec_out_of_bounds() -> TestResult {
    let mask = array_index_mask_nospec(15, 10);
    if mask != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_array_index_mask_nospec_boundary() -> TestResult {
    let mask = array_index_mask_nospec(10, 10);
    if mask != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_array_access_nospec() -> TestResult {
    let array = [10, 20, 30, 40, 50];
    let value = array_access_nospec(&array, 2);
    if value != 30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_array_access_nospec_first_element() -> TestResult {
    let array = [100, 200, 300];
    let value = array_access_nospec(&array, 0);
    if value != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_array_access_nospec_last_element() -> TestResult {
    let array = [1, 2, 3, 4, 5];
    let value = array_access_nospec(&array, 4);
    if value != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rsb_fill() -> TestResult {
    rsb_fill();
    TestResult::Pass
}

pub(crate) fn test_rsb_clear() -> TestResult {
    rsb_clear();
    TestResult::Pass
}

pub(crate) fn test_l1d_flush() -> TestResult {
    l1d_flush();
    TestResult::Pass
}

pub(crate) fn test_mds_clear() -> TestResult {
    mds_clear();
    TestResult::Pass
}

pub(crate) fn test_kernel_entry_mitigations() -> TestResult {
    kernel_entry_mitigations();
    TestResult::Pass
}

pub(crate) fn test_kernel_exit_mitigations() -> TestResult {
    kernel_exit_mitigations();
    TestResult::Pass
}

pub(crate) fn test_context_switch_mitigations() -> TestResult {
    context_switch_mitigations();
    TestResult::Pass
}

pub(crate) fn test_get_vulnerabilities() -> TestResult {
    let vulns = get_vulnerabilities();
    let _ = vulns.spectre_v1;
    TestResult::Pass
}

pub(crate) fn test_get_mitigation_status() -> TestResult {
    let status = get_mitigation_status();
    let _ = status.kpti_enabled;
    TestResult::Pass
}

pub(crate) fn test_are_mitigations_enabled() -> TestResult {
    let enabled = are_mitigations_enabled();
    let _ = enabled;
    TestResult::Pass
}

pub(crate) fn test_cpu_vulnerabilities_debug_format() -> TestResult {
    let vulns = CpuVulnerabilities::default();
    let debug_str = format!("{:?}", vulns);
    if !debug_str.contains("spectre_v1") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mitigation_status_debug_format() -> TestResult {
    let status = MitigationStatus::default();
    let debug_str = format!("{:?}", status);
    if !debug_str.contains("kpti_enabled") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vulnerability_fields_are_bools() -> TestResult {
    let vulns = CpuVulnerabilities::default();
    let _: bool = vulns.spectre_v1;
    let _: bool = vulns.meltdown;
    let _: bool = vulns.mds;
    TestResult::Pass
}

pub(crate) fn test_mitigation_fields_are_bools() -> TestResult {
    let status = MitigationStatus::default();
    let _: bool = status.kpti_enabled;
    let _: bool = status.retpoline_enabled;
    let _: bool = status.ibrs_enabled;
    TestResult::Pass
}
