// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

pub mod acct_record_tests;
pub mod address_space_types_tests;
pub mod clone_flags_tests;
pub mod core_types_tests;
pub mod elf_loader_types_tests;
pub mod fd_types_tests;
pub mod scheduler_types_tests;
pub mod thread_group_tests;
pub mod userspace_types_tests;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("process");

    // Accounting record tests (14)
    suite.add(TestCase::new("acct_flag_constants", acct_record_tests::acct_flag_constants));
    suite.add(TestCase::new("acct_flags_no_overlap", acct_record_tests::acct_flags_no_overlap));
    suite.add(TestCase::new("acct_record_default", acct_record_tests::acct_record_default));
    suite.add(TestCase::new("acct_record_with_values", acct_record_tests::acct_record_with_values));
    suite.add(TestCase::new("acct_record_clone", acct_record_tests::acct_record_clone));
    suite.add(TestCase::new("acct_record_comm_field", acct_record_tests::acct_record_comm_field));
    suite.add(TestCase::new(
        "acct_record_flag_combinations",
        acct_record_tests::acct_record_flag_combinations,
    ));
    suite.add(TestCase::new("process_record_new", acct_record_tests::process_record_new));
    suite.add(TestCase::new("process_record_clone", acct_record_tests::process_record_clone));
    suite.add(TestCase::new(
        "process_record_format_basic",
        acct_record_tests::process_record_format_basic,
    ));
    suite.add(TestCase::new(
        "process_record_format_signaled",
        acct_record_tests::process_record_format_signaled,
    ));
    suite.add(TestCase::new(
        "process_record_format_not_signaled",
        acct_record_tests::process_record_format_not_signaled,
    ));
    suite.add(TestCase::new(
        "process_record_with_capabilities",
        acct_record_tests::process_record_with_capabilities,
    ));
    suite.add(TestCase::new(
        "process_record_with_clone_flags",
        acct_record_tests::process_record_with_clone_flags,
    ));

    // Address space types tests (31)
    suite.add(TestCase::new(
        "page_size_constant",
        address_space_types_tests::test_page_size_constant,
    ));
    suite.add(TestCase::new(
        "large_page_size_constant",
        address_space_types_tests::test_large_page_size_constant,
    ));
    suite.add(TestCase::new(
        "huge_page_size_constant",
        address_space_types_tests::test_huge_page_size_constant,
    ));
    suite.add(TestCase::new(
        "user_space_end_constant",
        address_space_types_tests::test_user_space_end_constant,
    ));
    suite.add(TestCase::new(
        "kernel_space_start_constant",
        address_space_types_tests::test_kernel_space_start_constant,
    ));
    suite
        .add(TestCase::new("max_pcid_constant", address_space_types_tests::test_max_pcid_constant));
    suite.add(TestCase::new("vma_new", address_space_types_tests::test_vma_new));
    suite.add(TestCase::new("vma_size", address_space_types_tests::test_vma_size));
    suite.add(TestCase::new("vma_contains", address_space_types_tests::test_vma_contains));
    suite.add(TestCase::new("vma_overlaps", address_space_types_tests::test_vma_overlaps));
    suite.add(TestCase::new(
        "vma_overlaps_subset",
        address_space_types_tests::test_vma_overlaps_subset,
    ));
    suite.add(TestCase::new("vma_clone", address_space_types_tests::test_vma_clone));
    suite.add(TestCase::new(
        "protection_flags_read_only",
        address_space_types_tests::test_protection_flags_read_only,
    ));
    suite.add(TestCase::new(
        "protection_flags_write",
        address_space_types_tests::test_protection_flags_write,
    ));
    suite.add(TestCase::new(
        "protection_flags_exec",
        address_space_types_tests::test_protection_flags_exec,
    ));
    suite.add(TestCase::new(
        "protection_flags_combined",
        address_space_types_tests::test_protection_flags_combined,
    ));
    suite.add(TestCase::new(
        "protection_flags_all",
        address_space_types_tests::test_protection_flags_all,
    ));
    suite.add(TestCase::new(
        "pte_flags_addr_mask",
        address_space_types_tests::test_pte_flags_addr_mask,
    ));
    suite.add(TestCase::new(
        "address_space_boundaries",
        address_space_types_tests::test_address_space_boundaries,
    ));
    suite.add(TestCase::new(
        "page_sizes_ordering",
        address_space_types_tests::test_page_sizes_ordering,
    ));
    suite.add(TestCase::new(
        "page_sizes_power_of_two",
        address_space_types_tests::test_page_sizes_power_of_two,
    ));
    suite.add(TestCase::new(
        "page_size_alignment",
        address_space_types_tests::test_page_size_alignment,
    ));
    suite.add(TestCase::new("vma_size_zero", address_space_types_tests::test_vma_size_zero));
    suite.add(TestCase::new(
        "vma_adjacent_not_overlapping",
        address_space_types_tests::test_vma_adjacent_not_overlapping,
    ));
    suite.add(TestCase::new("vma_cow_flag", address_space_types_tests::test_vma_cow_flag));
    suite.add(TestCase::new(
        "vma_anonymous_flag",
        address_space_types_tests::test_vma_anonymous_flag,
    ));
    suite.add(TestCase::new(
        "vma_refcount_increment",
        address_space_types_tests::test_vma_refcount_increment,
    ));
    suite.add(TestCase::new(
        "protection_flags_default",
        address_space_types_tests::test_protection_flags_default,
    ));
    suite.add(TestCase::new(
        "protection_flags_equality",
        address_space_types_tests::test_protection_flags_equality,
    ));
    suite.add(TestCase::new(
        "protection_flags_to_pte_flags",
        address_space_types_tests::test_protection_flags_to_pte_flags,
    ));
    suite.add(TestCase::new(
        "protection_flags_no_exec_flag",
        address_space_types_tests::test_protection_flags_no_exec_flag,
    ));

    // Clone flags tests (14)
    suite.add(TestCase::new(
        "clone_flags_bit_positions",
        clone_flags_tests::clone_flags_bit_positions,
    ));
    suite.add(TestCase::new(
        "clone_flags_namespace_bits",
        clone_flags_tests::clone_flags_namespace_bits,
    ));
    suite.add(TestCase::new("clone_flags_tid_bits", clone_flags_tests::clone_flags_tid_bits));
    suite.add(TestCase::new("clone_flags_special", clone_flags_tests::clone_flags_special));
    suite.add(TestCase::new("clone_args_default", clone_flags_tests::clone_args_default));
    suite.add(TestCase::new("clone_args_with_flags", clone_flags_tests::clone_args_with_flags));
    suite.add(TestCase::new(
        "clone_args_thread_creation",
        clone_flags_tests::clone_args_thread_creation,
    ));
    suite.add(TestCase::new("clone_args_with_tls", clone_flags_tests::clone_args_with_tls));
    suite.add(TestCase::new(
        "clone_args_with_child_tid",
        clone_flags_tests::clone_args_with_child_tid,
    ));
    suite.add(TestCase::new(
        "clone_args_with_parent_tid",
        clone_flags_tests::clone_args_with_parent_tid,
    ));
    suite.add(TestCase::new("clone_args_clone", clone_flags_tests::clone_args_clone));
    suite.add(TestCase::new("clone_flags_no_overlap", clone_flags_tests::clone_flags_no_overlap));
    suite.add(TestCase::new(
        "clone_sighand_mask_value",
        clone_flags_tests::clone_sighand_mask_value,
    ));
    suite.add(TestCase::new(
        "clone_args_full_namespace_isolation",
        clone_flags_tests::clone_args_full_namespace_isolation,
    ));

    // Core types tests (24)
    suite.add(TestCase::new("process_state_variants", core_types_tests::process_state_variants));
    suite.add(TestCase::new(
        "process_state_zombie_with_code",
        core_types_tests::process_state_zombie_with_code,
    ));
    suite.add(TestCase::new(
        "process_state_terminated_with_code",
        core_types_tests::process_state_terminated_with_code,
    ));
    suite.add(TestCase::new("process_state_clone", core_types_tests::process_state_clone));
    suite.add(TestCase::new("priority_variants", core_types_tests::priority_variants));
    suite.add(TestCase::new("priority_not_equal", core_types_tests::priority_not_equal));
    suite.add(TestCase::new("priority_clone", core_types_tests::priority_clone));
    suite.add(TestCase::new("vma_basic", core_types_tests::vma_basic));
    suite.add(TestCase::new("vma_clone", core_types_tests::vma_clone));
    suite.add(TestCase::new("isolation_flags_default", core_types_tests::isolation_flags_default));
    suite.add(TestCase::new("isolation_flags_clone", core_types_tests::isolation_flags_clone));
    suite
        .add(TestCase::new("suspended_context_fields", core_types_tests::suspended_context_fields));
    suite.add(TestCase::new("suspended_context_clone", core_types_tests::suspended_context_clone));
    suite.add(TestCase::new("align_up_power_of_two", core_types_tests::align_up_power_of_two));
    suite.add(TestCase::new(
        "align_up_various_alignments",
        core_types_tests::align_up_various_alignments,
    ));
    suite.add(TestCase::new("align_up_alignment_1", core_types_tests::align_up_alignment_1));
    suite.add(TestCase::new("overlaps_no_overlap", core_types_tests::overlaps_no_overlap));
    suite.add(TestCase::new("overlaps_with_first", core_types_tests::overlaps_with_first));
    suite.add(TestCase::new("overlaps_adjacent", core_types_tests::overlaps_adjacent));
    suite.add(TestCase::new("overlaps_empty_vmas", core_types_tests::overlaps_empty_vmas));
    suite.add(TestCase::new("overlaps_zero_length", core_types_tests::overlaps_zero_length));
    suite.add(TestCase::new("pid_type_alias", core_types_tests::pid_type_alias));
    suite.add(TestCase::new("tid_type_alias", core_types_tests::tid_type_alias));

    // ELF loader types tests (30)
    suite.add(TestCase::new("elf64_header_size", elf_loader_types_tests::elf64_header_size));
    suite.add(TestCase::new(
        "elf64_program_header_size",
        elf_loader_types_tests::elf64_program_header_size,
    ));
    suite.add(TestCase::new(
        "elf64_section_header_size",
        elf_loader_types_tests::elf64_section_header_size,
    ));
    suite.add(TestCase::new("elf64_symbol_size", elf_loader_types_tests::elf64_symbol_size));
    suite.add(TestCase::new("elf64_rela_size", elf_loader_types_tests::elf64_rela_size));
    suite.add(TestCase::new("elf64_dyn_size", elf_loader_types_tests::elf64_dyn_size));
    suite.add(TestCase::new(
        "elf64_rela_symbol_index",
        elf_loader_types_tests::elf64_rela_symbol_index,
    ));
    suite.add(TestCase::new(
        "elf64_rela_relocation_type",
        elf_loader_types_tests::elf64_rela_relocation_type,
    ));
    suite.add(TestCase::new(
        "loaded_segment_end_addr",
        elf_loader_types_tests::loaded_segment_end_addr,
    ));
    suite.add(TestCase::new(
        "loaded_segment_is_readable",
        elf_loader_types_tests::loaded_segment_is_readable,
    ));
    suite.add(TestCase::new(
        "loaded_segment_is_writable",
        elf_loader_types_tests::loaded_segment_is_writable,
    ));
    suite.add(TestCase::new(
        "loaded_segment_is_executable",
        elf_loader_types_tests::loaded_segment_is_executable,
    ));
    suite.add(TestCase::new(
        "loaded_segment_bss_size",
        elf_loader_types_tests::loaded_segment_bss_size,
    ));
    suite.add(TestCase::new(
        "loaded_segment_bss_size_zero",
        elf_loader_types_tests::loaded_segment_bss_size_zero,
    ));
    suite.add(TestCase::new(
        "loaded_segment_get_file_params",
        elf_loader_types_tests::loaded_segment_get_file_params,
    ));
    suite.add(TestCase::new("loaded_segment_clone", elf_loader_types_tests::loaded_segment_clone));
    suite.add(TestCase::new(
        "loaded_elf_memory_size",
        elf_loader_types_tests::loaded_elf_memory_size,
    ));
    suite.add(TestCase::new("loaded_elf_has_tls", elf_loader_types_tests::loaded_elf_has_tls));
    suite.add(TestCase::new(
        "loaded_elf_get_tls_config",
        elf_loader_types_tests::loaded_elf_get_tls_config,
    ));
    suite.add(TestCase::new(
        "loaded_elf_needs_interp",
        elf_loader_types_tests::loaded_elf_needs_interp,
    ));
    suite
        .add(TestCase::new("loaded_elf_get_interp", elf_loader_types_tests::loaded_elf_get_interp));
    suite.add(TestCase::new(
        "loaded_elf_allows_exec_stack",
        elf_loader_types_tests::loaded_elf_allows_exec_stack,
    ));
    suite.add(TestCase::new(
        "loaded_elf_get_phdr_info",
        elf_loader_types_tests::loaded_elf_get_phdr_info,
    ));
    suite.add(TestCase::new("elf_error_variants", elf_loader_types_tests::elf_error_variants));
    suite.add(TestCase::new("elf_error_not_equal", elf_loader_types_tests::elf_error_not_equal));
    suite.add(TestCase::new("elf_error_display", elf_loader_types_tests::elf_error_display));
    suite.add(TestCase::new("elf_error_clone", elf_loader_types_tests::elf_error_clone));
    suite.add(TestCase::new("pf_flags_defined", elf_loader_types_tests::pf_flags_defined));
    suite.add(TestCase::new("pf_flag_combinations", elf_loader_types_tests::pf_flag_combinations));

    // FD types tests (34)
    suite.add(TestCase::new("fd_type_variants", fd_types_tests::fd_type_variants));
    suite.add(TestCase::new(
        "fd_type_not_equal_different_variants",
        fd_types_tests::fd_type_not_equal_different_variants,
    ));
    suite.add(TestCase::new("fd_entry_new", fd_types_tests::fd_entry_new));
    suite.add(TestCase::new("fd_entry_with_pipe_read", fd_types_tests::fd_entry_with_pipe_read));
    suite.add(TestCase::new("fd_entry_with_pipe_write", fd_types_tests::fd_entry_with_pipe_write));
    suite.add(TestCase::new("fd_entry_is_cloexec", fd_types_tests::fd_entry_is_cloexec));
    suite.add(TestCase::new("fd_cloexec_constant", fd_types_tests::fd_cloexec_constant));
    suite.add(TestCase::new("max_process_fds_constant", fd_types_tests::max_process_fds_constant));
    suite.add(TestCase::new("stdio_fds_constant", fd_types_tests::stdio_fds_constant));
    suite.add(TestCase::new("fd_entry_clone", fd_types_tests::fd_entry_clone));
    suite.add(TestCase::new("fd_table_stats_default", fd_types_tests::fd_table_stats_default));
    suite.add(TestCase::new("process_fd_table_new", fd_types_tests::process_fd_table_new));
    suite
        .add(TestCase::new("process_fd_table_allocate", fd_types_tests::process_fd_table_allocate));
    suite.add(TestCase::new(
        "process_fd_table_allocate_at",
        fd_types_tests::process_fd_table_allocate_at,
    ));
    suite.add(TestCase::new(
        "process_fd_table_allocate_min",
        fd_types_tests::process_fd_table_allocate_min,
    ));
    suite.add(TestCase::new("process_fd_table_get", fd_types_tests::process_fd_table_get));
    suite.add(TestCase::new("process_fd_table_remove", fd_types_tests::process_fd_table_remove));
    suite
        .add(TestCase::new("process_fd_table_is_valid", fd_types_tests::process_fd_table_is_valid));
    suite
        .add(TestCase::new("process_fd_table_get_type", fd_types_tests::process_fd_table_get_type));
    suite.add(TestCase::new(
        "process_fd_table_close_all",
        fd_types_tests::process_fd_table_close_all,
    ));
    suite.add(TestCase::new("process_fd_table_cloexec", fd_types_tests::process_fd_table_cloexec));
    suite.add(TestCase::new(
        "process_fd_table_status_flags",
        fd_types_tests::process_fd_table_status_flags,
    ));
    suite.add(TestCase::new("process_fd_table_dup", fd_types_tests::process_fd_table_dup));
    suite.add(TestCase::new("process_fd_table_dup2", fd_types_tests::process_fd_table_dup2));
    suite.add(TestCase::new(
        "process_fd_table_dup2_same_fd",
        fd_types_tests::process_fd_table_dup2_same_fd,
    ));
    suite.add(TestCase::new(
        "process_fd_table_dup2_replaces_existing",
        fd_types_tests::process_fd_table_dup2_replaces_existing,
    ));
    suite.add(TestCase::new(
        "process_fd_table_close_cloexec",
        fd_types_tests::process_fd_table_close_cloexec,
    ));
    suite.add(TestCase::new("process_fd_table_fork", fd_types_tests::process_fd_table_fork));
    suite.add(TestCase::new("process_fd_table_stats", fd_types_tests::process_fd_table_stats));
    suite.add(TestCase::new(
        "process_fd_table_allocate_at_invalid",
        fd_types_tests::process_fd_table_allocate_at_invalid,
    ));
    suite.add(TestCase::new(
        "process_fd_table_allocate_min_invalid",
        fd_types_tests::process_fd_table_allocate_min_invalid,
    ));
    suite.add(TestCase::new(
        "process_fd_table_dup2_invalid_new_fd",
        fd_types_tests::process_fd_table_dup2_invalid_new_fd,
    ));
    suite.add(TestCase::new(
        "process_fd_table_dup_nonexistent",
        fd_types_tests::process_fd_table_dup_nonexistent,
    ));
    suite.add(TestCase::new(
        "process_fd_table_set_cloexec_nonexistent",
        fd_types_tests::process_fd_table_set_cloexec_nonexistent,
    ));
    suite.add(TestCase::new(
        "process_fd_table_set_status_flags_nonexistent",
        fd_types_tests::process_fd_table_set_status_flags_nonexistent,
    ));

    // Scheduler types tests (35)
    suite.add(TestCase::new(
        "sched_policy_constants",
        scheduler_types_tests::sched_policy_constants,
    ));
    suite.add(TestCase::new("sched_priority_range", scheduler_types_tests::sched_priority_range));
    suite.add(TestCase::new("nice_value_range", scheduler_types_tests::nice_value_range));
    suite.add(TestCase::new("sched_flag_constants", scheduler_types_tests::sched_flag_constants));
    suite.add(TestCase::new(
        "ioprio_class_constants",
        scheduler_types_tests::ioprio_class_constants,
    ));
    suite.add(TestCase::new("ioprio_who_constants", scheduler_types_tests::ioprio_who_constants));
    suite.add(TestCase::new("timeslice_constants", scheduler_types_tests::timeslice_constants));
    suite.add(TestCase::new("sched_attr_default", scheduler_types_tests::sched_attr_default));
    suite.add(TestCase::new(
        "sched_attr_is_realtime_fifo",
        scheduler_types_tests::sched_attr_is_realtime_fifo,
    ));
    suite.add(TestCase::new(
        "sched_attr_is_realtime_rr",
        scheduler_types_tests::sched_attr_is_realtime_rr,
    ));
    suite.add(TestCase::new(
        "sched_attr_is_not_realtime",
        scheduler_types_tests::sched_attr_is_not_realtime,
    ));
    suite.add(TestCase::new(
        "sched_attr_effective_priority_normal",
        scheduler_types_tests::sched_attr_effective_priority_normal,
    ));
    suite.add(TestCase::new(
        "sched_attr_effective_priority_normal_with_nice",
        scheduler_types_tests::sched_attr_effective_priority_normal_with_nice,
    ));
    suite.add(TestCase::new(
        "sched_attr_effective_priority_fifo",
        scheduler_types_tests::sched_attr_effective_priority_fifo,
    ));
    suite.add(TestCase::new(
        "sched_attr_effective_priority_rr",
        scheduler_types_tests::sched_attr_effective_priority_rr,
    ));
    suite.add(TestCase::new(
        "sched_attr_effective_priority_deadline",
        scheduler_types_tests::sched_attr_effective_priority_deadline,
    ));
    suite.add(TestCase::new(
        "sched_attr_effective_priority_idle",
        scheduler_types_tests::sched_attr_effective_priority_idle,
    ));
    suite.add(TestCase::new(
        "sched_attr_effective_priority_batch",
        scheduler_types_tests::sched_attr_effective_priority_batch,
    ));
    suite.add(TestCase::new(
        "sched_attr_can_run_on_cpu",
        scheduler_types_tests::sched_attr_can_run_on_cpu,
    ));
    suite.add(TestCase::new(
        "sched_attr_can_run_on_cpu_high_cpu",
        scheduler_types_tests::sched_attr_can_run_on_cpu_high_cpu,
    ));
    suite.add(TestCase::new(
        "sched_attr_get_timeslice_fifo",
        scheduler_types_tests::sched_attr_get_timeslice_fifo,
    ));
    suite.add(TestCase::new(
        "sched_attr_get_timeslice_rr",
        scheduler_types_tests::sched_attr_get_timeslice_rr,
    ));
    suite.add(TestCase::new(
        "sched_attr_get_timeslice_normal",
        scheduler_types_tests::sched_attr_get_timeslice_normal,
    ));
    suite.add(TestCase::new("sched_attr_clone", scheduler_types_tests::sched_attr_clone));
    suite.add(TestCase::new("encode_decode_ioprio", scheduler_types_tests::encode_decode_ioprio));
    suite.add(TestCase::new(
        "encode_decode_ioprio_rt",
        scheduler_types_tests::encode_decode_ioprio_rt,
    ));
    suite.add(TestCase::new(
        "encode_decode_ioprio_idle",
        scheduler_types_tests::encode_decode_ioprio_idle,
    ));
    suite.add(TestCase::new(
        "encode_ioprio_max_level",
        scheduler_types_tests::encode_ioprio_max_level,
    ));
    suite.add(TestCase::new("sched_param_default", scheduler_types_tests::sched_param_default));
    suite.add(TestCase::new(
        "sched_param_with_priority",
        scheduler_types_tests::sched_param_with_priority,
    ));
    suite.add(TestCase::new(
        "linux_sched_attr_default",
        scheduler_types_tests::linux_sched_attr_default,
    ));
    suite.add(TestCase::new(
        "linux_sched_attr_clone",
        scheduler_types_tests::linux_sched_attr_clone,
    ));
    suite.add(TestCase::new(
        "sched_policy_stats_default",
        scheduler_types_tests::sched_policy_stats_default,
    ));
    suite.add(TestCase::new(
        "sched_policy_stats_clone",
        scheduler_types_tests::sched_policy_stats_clone,
    ));

    // Thread group tests (11)
    suite.add(TestCase::new("thread_group_new", thread_group_tests::thread_group_new));
    suite
        .add(TestCase::new("thread_group_add_thread", thread_group_tests::thread_group_add_thread));
    suite.add(TestCase::new(
        "thread_group_remove_thread",
        thread_group_tests::thread_group_remove_thread,
    ));
    suite.add(TestCase::new(
        "thread_group_remove_nonexistent",
        thread_group_tests::thread_group_remove_nonexistent,
    ));
    suite.add(TestCase::new("thread_group_is_leader", thread_group_tests::thread_group_is_leader));
    suite.add(TestCase::new(
        "thread_group_thread_count_atomic",
        thread_group_tests::thread_group_thread_count_atomic,
    ));
    suite.add(TestCase::new(
        "thread_group_remove_leader",
        thread_group_tests::thread_group_remove_leader,
    ));
    suite.add(TestCase::new(
        "thread_group_tgid_unchanged",
        thread_group_tests::thread_group_tgid_unchanged,
    ));
    suite.add(TestCase::new(
        "thread_group_threads_list",
        thread_group_tests::thread_group_threads_list,
    ));
    suite.add(TestCase::new(
        "thread_group_remove_all_except_leader",
        thread_group_tests::thread_group_remove_all_except_leader,
    ));
    suite.add(TestCase::new(
        "thread_group_multiple_add_remove",
        thread_group_tests::thread_group_multiple_add_remove,
    ));

    // Userspace types tests (58)
    suite.add(TestCase::new("user_cs_constant", userspace_types_tests::test_user_cs_constant));
    suite.add(TestCase::new("user_ds_constant", userspace_types_tests::test_user_ds_constant));
    suite.add(TestCase::new("kernel_cs_constant", userspace_types_tests::test_kernel_cs_constant));
    suite.add(TestCase::new("kernel_ds_constant", userspace_types_tests::test_kernel_ds_constant));
    suite.add(TestCase::new(
        "user_rflags_constant",
        userspace_types_tests::test_user_rflags_constant,
    ));
    suite.add(TestCase::new(
        "user_stack_size_constant",
        userspace_types_tests::test_user_stack_size_constant,
    ));
    suite.add(TestCase::new(
        "kernel_stack_size_constant",
        userspace_types_tests::test_kernel_stack_size_constant,
    ));
    suite.add(TestCase::new(
        "user_stack_base_constant",
        userspace_types_tests::test_user_stack_base_constant,
    ));
    suite.add(TestCase::new(
        "user_heap_start_constant",
        userspace_types_tests::test_user_heap_start_constant,
    ));
    suite.add(TestCase::new(
        "user_code_start_constant",
        userspace_types_tests::test_user_code_start_constant,
    ));
    suite.add(TestCase::new(
        "segment_selectors_ring_3",
        userspace_types_tests::test_segment_selectors_ring_3,
    ));
    suite.add(TestCase::new(
        "segment_selectors_ring_0",
        userspace_types_tests::test_segment_selectors_ring_0,
    ));
    suite.add(TestCase::new("thread_state_ready", userspace_types_tests::test_thread_state_ready));
    suite.add(TestCase::new(
        "thread_state_running",
        userspace_types_tests::test_thread_state_running,
    ));
    suite.add(TestCase::new(
        "thread_state_blocked",
        userspace_types_tests::test_thread_state_blocked,
    ));
    suite.add(TestCase::new(
        "thread_state_sleeping",
        userspace_types_tests::test_thread_state_sleeping,
    ));
    suite
        .add(TestCase::new("thread_state_zombie", userspace_types_tests::test_thread_state_zombie));
    suite.add(TestCase::new(
        "thread_state_stopped",
        userspace_types_tests::test_thread_state_stopped,
    ));
    suite.add(TestCase::new(
        "thread_state_equality",
        userspace_types_tests::test_thread_state_equality,
    ));
    suite.add(TestCase::new("thread_state_clone", userspace_types_tests::test_thread_state_clone));
    suite.add(TestCase::new("thread_state_copy", userspace_types_tests::test_thread_state_copy));
    suite.add(TestCase::new("block_reason_io", userspace_types_tests::test_block_reason_io));
    suite.add(TestCase::new("block_reason_lock", userspace_types_tests::test_block_reason_lock));
    suite.add(TestCase::new("block_reason_futex", userspace_types_tests::test_block_reason_futex));
    suite.add(TestCase::new("block_reason_wait", userspace_types_tests::test_block_reason_wait));
    suite
        .add(TestCase::new("block_reason_signal", userspace_types_tests::test_block_reason_signal));
    suite.add(TestCase::new("block_reason_ipc", userspace_types_tests::test_block_reason_ipc));
    suite.add(TestCase::new(
        "block_reason_futex_equality",
        userspace_types_tests::test_block_reason_futex_equality,
    ));
    suite.add(TestCase::new(
        "block_reason_different_variants",
        userspace_types_tests::test_block_reason_different_variants,
    ));
    suite.add(TestCase::new("block_reason_clone", userspace_types_tests::test_block_reason_clone));
    suite.add(TestCase::new("fpu_state_default", userspace_types_tests::test_fpu_state_default));
    suite.add(TestCase::new("fpu_state_size", userspace_types_tests::test_fpu_state_size));
    suite
        .add(TestCase::new("fpu_state_alignment", userspace_types_tests::test_fpu_state_alignment));
    suite.add(TestCase::new(
        "interrupt_frame_for_user_entry",
        userspace_types_tests::test_interrupt_frame_for_user_entry,
    ));
    suite.add(TestCase::new(
        "interrupt_frame_clone",
        userspace_types_tests::test_interrupt_frame_clone,
    ));
    suite.add(TestCase::new(
        "interrupt_frame_copy",
        userspace_types_tests::test_interrupt_frame_copy,
    ));
    suite.add(TestCase::new(
        "interrupt_frame_size",
        userspace_types_tests::test_interrupt_frame_size,
    ));
    suite.add(TestCase::new(
        "user_context_default",
        userspace_types_tests::test_user_context_default,
    ));
    suite.add(TestCase::new("user_context_size", userspace_types_tests::test_user_context_size));
    suite.add(TestCase::new("user_context_clone", userspace_types_tests::test_user_context_clone));
    suite.add(TestCase::new("user_context_copy", userspace_types_tests::test_user_context_copy));
    suite
        .add(TestCase::new("exec_context_fields", userspace_types_tests::test_exec_context_fields));
    suite.add(TestCase::new("exec_context_size", userspace_types_tests::test_exec_context_size));
    suite.add(TestCase::new(
        "user_space_addresses_valid",
        userspace_types_tests::test_user_space_addresses_valid,
    ));
    suite.add(TestCase::new(
        "user_space_layout_order",
        userspace_types_tests::test_user_space_layout_order,
    ));
    suite.add(TestCase::new(
        "user_rflags_interrupt_enabled",
        userspace_types_tests::test_user_rflags_interrupt_enabled,
    ));
    suite.add(TestCase::new(
        "user_rflags_reserved_bit_set",
        userspace_types_tests::test_user_rflags_reserved_bit_set,
    ));
    suite.add(TestCase::new(
        "stack_sizes_power_of_two",
        userspace_types_tests::test_stack_sizes_power_of_two,
    ));
    suite.add(TestCase::new(
        "kernel_stack_smaller_than_user",
        userspace_types_tests::test_kernel_stack_smaller_than_user,
    ));
    suite.add(TestCase::new(
        "thread_state_all_variants",
        userspace_types_tests::test_thread_state_all_variants,
    ));
    suite.add(TestCase::new(
        "block_reason_all_simple_variants",
        userspace_types_tests::test_block_reason_all_simple_variants,
    ));
    suite.add(TestCase::new(
        "interrupt_frame_fields",
        userspace_types_tests::test_interrupt_frame_fields,
    ));
    suite.add(TestCase::new(
        "user_context_all_registers",
        userspace_types_tests::test_user_context_all_registers,
    ));
    suite.add(TestCase::new(
        "segment_selector_gdt_index",
        userspace_types_tests::test_segment_selector_gdt_index,
    ));
    suite.add(TestCase::new("user_context_debug", userspace_types_tests::test_user_context_debug));
    suite.add(TestCase::new(
        "interrupt_frame_debug",
        userspace_types_tests::test_interrupt_frame_debug,
    ));
    suite.add(TestCase::new("thread_state_debug", userspace_types_tests::test_thread_state_debug));
    suite.add(TestCase::new("block_reason_debug", userspace_types_tests::test_block_reason_debug));

    suite.run()
}
