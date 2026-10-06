//! Fixed invoice-admission windows for Paykit readers whose wallet setup is
//! not finished.
//!
//! Paykit answers `503 reader_setup_pending` (no App Registry yet) or
//! `502 reader_registry_malformed` after its own bounded reads. A viewer may
//! resubmit the same Bundle ID while the reader finishes setup, but only
//! inside one fixed window opened by the first such refusal. Later refusals
//! never move the window, and once it has passed the Bundle ID is refused
//! without another Paykit call.
//!
//! Windows are process-local, like the submission rate limits: a restart
//! forgets them. Expired windows are kept for [`RETENTION`] so a late
//! resubmission still finds them; past [`MAX_WINDOWS`] the oldest window is
//! dropped.

use std::collections::HashMap;
use std::sync::Mutex;

use locks_core::ids::{BundleId, CreatorPubky};
use time::{Duration, OffsetDateTime};

/// How long a reader has, from the first refusal, to finish wallet setup.
pub const ADMISSION_WINDOW: Duration = Duration::minutes(10);
/// How long an opened window is remembered.
pub const RETENTION: Duration = Duration::hours(24);
/// Upper bound on remembered windows.
pub const MAX_WINDOWS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReaderAdmissionKey {
    pub creator: CreatorPubky,
    pub bundle_id: BundleId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderAdmissionWindow {
    /// No refusal has been seen for this Bundle ID.
    NotOpened,
    /// Resubmission is allowed until `deadline`.
    Open { deadline: OffsetDateTime },
    /// The window has passed; the Bundle ID cannot be admitted.
    Expired,
}

#[derive(Debug, Default)]
pub struct ReaderAdmissionWindows {
    opened_at: Mutex<HashMap<ReaderAdmissionKey, OffsetDateTime>>,
}

impl ReaderAdmissionWindows {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn window(&self, key: &ReaderAdmissionKey, now: OffsetDateTime) -> ReaderAdmissionWindow {
        let windows = self
            .opened_at
            .lock()
            .expect("admission window mutex poisoned");
        match windows.get(key) {
            None => ReaderAdmissionWindow::NotOpened,
            Some(opened_at) => classify(*opened_at, now),
        }
    }

    /// Opens the window at `now` unless one is already open for `key`, and
    /// returns the window as it stands afterwards.
    pub fn record_refusal(
        &self,
        key: &ReaderAdmissionKey,
        now: OffsetDateTime,
    ) -> ReaderAdmissionWindow {
        let mut windows = self
            .opened_at
            .lock()
            .expect("admission window mutex poisoned");
        if !windows.contains_key(key) {
            windows.retain(|_, opened_at| now - *opened_at < RETENTION);
            if windows.len() >= MAX_WINDOWS
                && let Some(oldest) = windows
                    .iter()
                    .min_by_key(|(_, opened_at)| **opened_at)
                    .map(|(key, _)| key.clone())
            {
                windows.remove(&oldest);
            }
            windows.insert(key.clone(), now);
        }
        classify(windows[key], now)
    }

    /// Forgets the window once the Bundle ID was admitted or refused for good.
    pub fn close(&self, key: &ReaderAdmissionKey) {
        self.opened_at
            .lock()
            .expect("admission window mutex poisoned")
            .remove(key);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.opened_at.lock().unwrap().len()
    }
}

fn classify(opened_at: OffsetDateTime, now: OffsetDateTime) -> ReaderAdmissionWindow {
    let deadline = opened_at + ADMISSION_WINDOW;
    if now < deadline {
        ReaderAdmissionWindow::Open { deadline }
    } else {
        ReaderAdmissionWindow::Expired
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use time::macros::datetime;

    use super::*;

    fn key(bundle: &str) -> ReaderAdmissionKey {
        ReaderAdmissionKey {
            creator: CreatorPubky::from_str(
                "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo",
            )
            .unwrap(),
            bundle_id: BundleId::from_str(bundle).unwrap(),
        }
    }

    const BUNDLE: &str = "000G40R40M30E209185GR38E1W";
    const OTHER: &str = "000G40R40M30E209185GR38E2W";

    #[test]
    fn first_refusal_opens_a_fixed_window_that_later_refusals_never_move() {
        let windows = ReaderAdmissionWindows::new();
        let start = datetime!(2026-10-06 12:00:00 UTC);
        let deadline = start + ADMISSION_WINDOW;

        assert_eq!(
            windows.window(&key(BUNDLE), start),
            ReaderAdmissionWindow::NotOpened
        );
        assert_eq!(
            windows.record_refusal(&key(BUNDLE), start),
            ReaderAdmissionWindow::Open { deadline }
        );
        assert_eq!(
            windows.record_refusal(&key(BUNDLE), start + Duration::minutes(9)),
            ReaderAdmissionWindow::Open { deadline }
        );
        assert_eq!(
            windows.window(&key(BUNDLE), deadline - Duration::seconds(1)),
            ReaderAdmissionWindow::Open { deadline }
        );
        assert_eq!(
            windows.window(&key(BUNDLE), deadline),
            ReaderAdmissionWindow::Expired
        );
        assert_eq!(
            windows.record_refusal(&key(BUNDLE), deadline + Duration::minutes(1)),
            ReaderAdmissionWindow::Expired
        );
        assert_eq!(
            windows.window(&key(OTHER), deadline),
            ReaderAdmissionWindow::NotOpened
        );
    }

    #[test]
    fn closing_forgets_the_window() {
        let windows = ReaderAdmissionWindows::new();
        let start = datetime!(2026-10-06 12:00:00 UTC);
        windows.record_refusal(&key(BUNDLE), start);
        windows.close(&key(BUNDLE));
        assert_eq!(
            windows.window(&key(BUNDLE), start),
            ReaderAdmissionWindow::NotOpened
        );
    }

    #[test]
    fn expired_windows_are_kept_for_retention_then_pruned_on_insert() {
        let windows = ReaderAdmissionWindows::new();
        let start = datetime!(2026-10-06 12:00:00 UTC);
        windows.record_refusal(&key(BUNDLE), start);
        assert_eq!(
            windows.window(&key(BUNDLE), start + RETENTION - Duration::seconds(1)),
            ReaderAdmissionWindow::Expired
        );
        windows.record_refusal(&key(OTHER), start + RETENTION);
        assert_eq!(windows.len(), 1);
        assert_eq!(
            windows.window(&key(BUNDLE), start + RETENTION),
            ReaderAdmissionWindow::NotOpened
        );
    }

    #[test]
    fn the_oldest_window_is_dropped_at_capacity() {
        let windows = ReaderAdmissionWindows::new();
        let start = datetime!(2026-10-06 12:00:00 UTC);
        let keys: Vec<_> = (0..=MAX_WINDOWS)
            .map(|index| ReaderAdmissionKey {
                creator: key(BUNDLE).creator,
                bundle_id: BundleId::from_bytes((index as u128).to_be_bytes()),
            })
            .collect();
        for (offset, key) in keys.iter().enumerate() {
            windows.record_refusal(key, start + Duration::milliseconds(offset as i64));
        }
        assert_eq!(windows.len(), MAX_WINDOWS);
        assert_eq!(
            windows.window(&keys[0], start),
            ReaderAdmissionWindow::NotOpened
        );
        assert!(matches!(
            windows.window(&keys[MAX_WINDOWS], start),
            ReaderAdmissionWindow::Open { .. }
        ));
    }
}
