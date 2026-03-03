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

pub const CLASS_UNCLASSIFIED: u8 = 0x00;
pub const CLASS_MASS_STORAGE: u8 = 0x01;
pub const CLASS_NETWORK: u8 = 0x02;
pub const CLASS_DISPLAY: u8 = 0x03;
pub const CLASS_MULTIMEDIA: u8 = 0x04;
pub const CLASS_MEMORY: u8 = 0x05;
pub const CLASS_BRIDGE: u8 = 0x06;
pub const CLASS_SIMPLE_COMM: u8 = 0x07;
pub const CLASS_BASE_PERIPHERAL: u8 = 0x08;
pub const CLASS_INPUT: u8 = 0x09;
pub const CLASS_DOCKING: u8 = 0x0A;
pub const CLASS_PROCESSOR: u8 = 0x0B;
pub const CLASS_SERIAL_BUS: u8 = 0x0C;
pub const CLASS_WIRELESS: u8 = 0x0D;
pub const CLASS_INTELLIGENT_IO: u8 = 0x0E;
pub const CLASS_SATELLITE_COMM: u8 = 0x0F;
pub const CLASS_ENCRYPTION: u8 = 0x10;
pub const CLASS_SIGNAL_PROCESSING: u8 = 0x11;
pub const CLASS_PROCESSING_ACCELERATOR: u8 = 0x12;
pub const CLASS_NON_ESSENTIAL: u8 = 0x13;
pub const CLASS_COPROCESSOR: u8 = 0x40;
pub const CLASS_UNASSIGNED: u8 = 0xFF;

pub const SUBCLASS_STORAGE_SCSI: u8 = 0x00;
pub const SUBCLASS_STORAGE_IDE: u8 = 0x01;
pub const SUBCLASS_STORAGE_FLOPPY: u8 = 0x02;
pub const SUBCLASS_STORAGE_IPI: u8 = 0x03;
pub const SUBCLASS_STORAGE_RAID: u8 = 0x04;
pub const SUBCLASS_STORAGE_ATA: u8 = 0x05;
pub const SUBCLASS_STORAGE_SATA: u8 = 0x06;
pub const SUBCLASS_STORAGE_SAS: u8 = 0x07;
pub const SUBCLASS_STORAGE_NVM: u8 = 0x08;
pub const SUBCLASS_STORAGE_UFS: u8 = 0x09;
pub const SUBCLASS_STORAGE_OTHER: u8 = 0x80;

pub const SUBCLASS_NETWORK_ETHERNET: u8 = 0x00;
pub const SUBCLASS_NETWORK_TOKEN_RING: u8 = 0x01;
pub const SUBCLASS_NETWORK_FDDI: u8 = 0x02;
pub const SUBCLASS_NETWORK_ATM: u8 = 0x03;
pub const SUBCLASS_NETWORK_ISDN: u8 = 0x04;
pub const SUBCLASS_NETWORK_WORLDFIP: u8 = 0x05;
pub const SUBCLASS_NETWORK_PICMG: u8 = 0x06;
pub const SUBCLASS_NETWORK_INFINIBAND: u8 = 0x07;
pub const SUBCLASS_NETWORK_FABRIC: u8 = 0x08;
pub const SUBCLASS_NETWORK_OTHER: u8 = 0x80;

pub const SUBCLASS_DISPLAY_VGA: u8 = 0x00;
pub const SUBCLASS_DISPLAY_XGA: u8 = 0x01;
pub const SUBCLASS_DISPLAY_3D: u8 = 0x02;
pub const SUBCLASS_DISPLAY_OTHER: u8 = 0x80;

pub const SUBCLASS_SERIAL_FIREWIRE: u8 = 0x00;
pub const SUBCLASS_SERIAL_ACCESS_BUS: u8 = 0x01;
pub const SUBCLASS_SERIAL_SSA: u8 = 0x02;
pub const SUBCLASS_SERIAL_USB: u8 = 0x03;
pub const SUBCLASS_SERIAL_FIBRE: u8 = 0x04;
pub const SUBCLASS_SERIAL_SMBUS: u8 = 0x05;
pub const SUBCLASS_SERIAL_INFINIBAND: u8 = 0x06;
pub const SUBCLASS_SERIAL_IPMI: u8 = 0x07;
pub const SUBCLASS_SERIAL_SERCOS: u8 = 0x08;
pub const SUBCLASS_SERIAL_CANBUS: u8 = 0x09;
pub const SUBCLASS_SERIAL_OTHER: u8 = 0x80;

pub const PROGIF_OHCI: u8 = 0x10;
pub const PROGIF_EHCI: u8 = 0x20;
pub const PROGIF_XHCI: u8 = 0x30;
pub const PROGIF_UHCI: u8 = 0x00;
pub const PROGIF_USB4: u8 = 0x40;
pub const PROGIF_DEVICE: u8 = 0xFE;

pub const PROGIF_NVME: u8 = 0x02;
pub const PROGIF_NVME_ADMIN: u8 = 0x03;

pub const PROGIF_AHCI: u8 = 0x01;
pub const PROGIF_AHCI_RAID: u8 = 0x04;

pub const VENDOR_INTEL: u16 = 0x8086;
pub const VENDOR_AMD: u16 = 0x1022;
pub const VENDOR_NVIDIA: u16 = 0x10DE;
pub const VENDOR_QEMU: u16 = 0x1234;
pub const VENDOR_VIRTIO: u16 = 0x1AF4;
pub const VENDOR_REALTEK: u16 = 0x10EC;
pub const VENDOR_BROADCOM: u16 = 0x14E4;
pub const VENDOR_RED_HAT: u16 = 0x1B36;
