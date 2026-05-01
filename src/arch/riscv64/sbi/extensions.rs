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

use super::base::probe_extension_base;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extension {
    Base,
    Timer,
    Ipi,
    Rfence,
    Hsm,
    Srst,
    Pmu,
    Dbcn,
    Susp,
    Cppc,
    Legacy(usize),
}

impl Extension {
    pub fn eid(&self) -> usize {
        match self {
            Self::Base => 0x10,
            Self::Timer => 0x54494D45,
            Self::Ipi => 0x735049,
            Self::Rfence => 0x52464E43,
            Self::Hsm => 0x48534D,
            Self::Srst => 0x53525354,
            Self::Pmu => 0x504D55,
            Self::Dbcn => 0x4442434E,
            Self::Susp => 0x53555350,
            Self::Cppc => 0x43505043,
            Self::Legacy(eid) => *eid,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Base => "Base",
            Self::Timer => "Timer",
            Self::Ipi => "IPI",
            Self::Rfence => "Remote Fence",
            Self::Hsm => "Hart State Management",
            Self::Srst => "System Reset",
            Self::Pmu => "Performance Monitoring",
            Self::Dbcn => "Debug Console",
            Self::Susp => "System Suspend",
            Self::Cppc => "CPPC",
            Self::Legacy(_) => "Legacy",
        }
    }
}

pub fn probe_extension(ext: Extension) -> bool {
    probe_extension_base(ext.eid()).unwrap_or(false)
}

pub fn has_timer() -> bool {
    probe_extension(Extension::Timer)
}

pub fn has_ipi() -> bool {
    probe_extension(Extension::Ipi)
}

pub fn has_rfence() -> bool {
    probe_extension(Extension::Rfence)
}

pub fn has_hsm() -> bool {
    probe_extension(Extension::Hsm)
}

pub fn has_srst() -> bool {
    probe_extension(Extension::Srst)
}

pub fn has_pmu() -> bool {
    probe_extension(Extension::Pmu)
}

pub fn has_dbcn() -> bool {
    probe_extension(Extension::Dbcn)
}

pub fn has_susp() -> bool {
    probe_extension(Extension::Susp)
}

#[derive(Debug, Clone)]
pub struct SbiCapabilities {
    pub timer: bool,
    pub ipi: bool,
    pub rfence: bool,
    pub hsm: bool,
    pub srst: bool,
    pub pmu: bool,
    pub dbcn: bool,
    pub susp: bool,
}

impl SbiCapabilities {
    pub fn discover() -> Self {
        Self {
            timer: has_timer(),
            ipi: has_ipi(),
            rfence: has_rfence(),
            hsm: has_hsm(),
            srst: has_srst(),
            pmu: has_pmu(),
            dbcn: has_dbcn(),
            susp: has_susp(),
        }
    }
}
