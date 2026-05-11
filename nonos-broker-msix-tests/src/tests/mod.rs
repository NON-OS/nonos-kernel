// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

mod intx_setup;
mod lock;
mod msix_setup;
mod pci_setup;

mod already_bound;
mod bad_msix_bar;
mod e1000_descriptor_layout;
mod e1000_protocol_rejects;
mod e1000_protocol_round_trip;
mod e1000_rx_ring;
mod e1000_tx_ring;
mod intx_msix_only_device;
mod intx_succeeds;
mod mmio_msix_pba_overlap;
mod mmio_msix_table_overlap;
mod mmio_other_bar_allowed;
mod no_msix_cap;
mod partial_program_rollback;
mod pci_command_bme_accept;
mod pci_command_no_op;
mod pci_command_rejects_other_bits;
mod pci_forbidden_offsets;
mod pci_msix_both_bits;
mod pci_msix_enable;
mod pci_msix_function_mask;
mod pci_msix_no_cap_rejects;
mod pci_msix_rejects_other_bits;
mod pci_msix_wrong_offset;
mod pci_resolve_no_handle;
mod pci_resolve_stale_epoch;
mod pci_resolve_unclaimed;
mod pool_exhaustion;
mod release_keeps_others;
mod release_last_disables;
mod unclaimed_device;
mod vector_count_over_pool;
mod vector_count_over_table;
mod vector_count_zero;
