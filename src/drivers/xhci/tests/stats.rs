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

#[cfg(test)]
mod tests {
    use crate::drivers::xhci::stats;

    #[test]
    fn test_stats_increment() {
        let stats = stats::XhciStatistics::new();

        stats.inc_interrupts();
        stats.inc_commands();
        stats.inc_transfers();
        stats.add_bytes(1024);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.interrupts, 1);
        assert_eq!(snapshot.commands_completed, 1);
        assert_eq!(snapshot.transfers, 1);
        assert_eq!(snapshot.bytes_transferred, 1024);
    }

    #[test]
    fn test_stats_total_errors() {
        let stats = stats::XhciStatistics::new();

        stats.inc_timeouts();
        stats.inc_stalls();

        assert_eq!(stats.total_errors(), 2);
    }

    #[test]
    fn test_stats_error_rate() {
        let mut snapshot = stats::XhciStats::new();
        snapshot.transfers = 90;
        snapshot.errors = 10;

        let rate = snapshot.error_rate();
        assert!((rate - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_controller_health() {
        let mut snapshot = stats::XhciStats::new();
        snapshot.transfers = 100;
        snapshot.errors = 0;

        assert_eq!(
            stats::ControllerHealth::from_stats(&snapshot),
            stats::ControllerHealth::Healthy
        );

        snapshot.errors = 5;
        assert_eq!(
            stats::ControllerHealth::from_stats(&snapshot),
            stats::ControllerHealth::Warning
        );

        snapshot.errors = 20;
        assert_eq!(
            stats::ControllerHealth::from_stats(&snapshot),
            stats::ControllerHealth::Critical
        );
    }
}
