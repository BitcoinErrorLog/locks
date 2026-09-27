use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;

use crate::application::errors::ApplicationError;
use crate::application::ports::{
    Clock, CreatorAuthorityManager, CreatorAuthorityStatus, CreatorAuthorityStore,
};

/// How one background pass chooses and spaces homeserver revalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityRevalidationPolicy {
    /// A row is due when its last real check is strictly older than this.
    pub stale_after: time::Duration,
    /// Maximum creators contacted in one pass.
    pub batch_size: u32,
    /// Maximum homeserver checks in flight during the pass.
    pub concurrency: usize,
    /// Minimum delay between starting two checks in the same pass.
    pub stagger: Duration,
}

/// What one pass did. Refusals and honors are whatever the manager recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuthorityRevalidationReport {
    /// Creators selected for this pass.
    pub selected: usize,
    /// Homeserver honored the stored authority. The manager recorded that.
    pub honored: usize,
    /// Homeserver refused the stored authority. The manager recorded that.
    pub refused: usize,
    /// The check did not produce a homeserver answer, so the stored validity was left as it was.
    pub left_unchanged: usize,
}

/// Re-runs the real authority check for a small batch of stale rows.
///
/// Each check goes through [`CreatorAuthorityManager::revalidate_creator_authority`], the same
/// call content, entitlement, and payment-path I/O use, so an honored or refused homeserver
/// answer is recorded the same way. A pass takes at most `batch_size` creators and starts at
/// most `concurrency` checks at once, with `stagger` between starts.
pub async fn revalidate_stale_creator_authorities(
    store: &dyn CreatorAuthorityStore,
    manager: Arc<dyn CreatorAuthorityManager>,
    clock: &dyn Clock,
    policy: AuthorityRevalidationPolicy,
) -> Result<AuthorityRevalidationReport, ApplicationError> {
    let cutoff = clock.now() - policy.stale_after;
    let due = store
        .list_creator_authorities_checked_before(cutoff, policy.batch_size)
        .await?;
    let concurrency = policy.concurrency.max(1);
    let mut report = AuthorityRevalidationReport {
        selected: due.len(),
        ..AuthorityRevalidationReport::default()
    };
    let mut in_flight = JoinSet::new();
    for (index, creator) in due.into_iter().enumerate() {
        if index > 0 && !policy.stagger.is_zero() {
            tokio::time::sleep(policy.stagger).await;
        }
        while in_flight.len() >= concurrency {
            record_join(&mut report, in_flight.join_next().await);
        }
        let manager = Arc::clone(&manager);
        in_flight.spawn(async move { manager.revalidate_creator_authority(&creator).await });
    }
    while let Some(joined) = in_flight.join_next().await {
        record_join(&mut report, Some(joined));
    }
    Ok(report)
}

fn record_join(
    report: &mut AuthorityRevalidationReport,
    joined: Option<
        Result<Result<CreatorAuthorityStatus, ApplicationError>, tokio::task::JoinError>,
    >,
) {
    match joined {
        Some(Ok(Ok(_))) => report.honored += 1,
        Some(Ok(Err(ApplicationError::CreatorAuthorityRefused))) => report.refused += 1,
        Some(Ok(Err(_))) | Some(Err(_)) => report.left_unchanged += 1,
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use locks_core::ids::CreatorPubky;
    use time::OffsetDateTime;
    use tokio::sync::Notify;

    use super::{AuthorityRevalidationPolicy, revalidate_stale_creator_authorities};
    use crate::application::errors::ApplicationError;
    use crate::application::models::{
        CreatorAuthorityAuthKind, CreatorAuthorityCheckOutcome, CreatorAuthorityRecord,
        CreatorAuthoritySecret, CreatorAuthorityValidity,
    };
    use crate::application::ports::{Clock, CreatorAuthorityManager, CreatorAuthorityStore};
    use crate::application::use_cases::get_creator_authority_status::get_public_creator_authority_status;
    use crate::infrastructure::pubky::{
        LegacyCookieCreatorAuthorityManager, LegacyCookieSessionRevalidator,
    };

    #[tokio::test]
    async fn a_revoked_stale_authority_stops_answering_authorized() {
        let memory = Arc::new(MemoryStore::new());
        let creator = creator("pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy");
        memory.insert(authority(&creator, Some(hours_ago(7)), None));
        let clock = NowClock;
        let before = get_public_creator_authority_status(
            &StoreHandle(Arc::clone(&memory)),
            &clock,
            creator.clone(),
        )
        .await
        .unwrap();
        assert!(before.authorized);

        let report = revalidate_stale_creator_authorities(
            &StoreHandle(Arc::clone(&memory)),
            manager(Arc::clone(&memory), ScriptedRevalidator::refused()),
            &clock,
            policy(4, 1, 0),
        )
        .await
        .unwrap();

        assert_eq!(report.selected, 1);
        assert_eq!(report.refused, 1);
        assert_eq!(report.honored, 0);
        let after = get_public_creator_authority_status(&StoreHandle(memory), &clock, creator)
            .await
            .unwrap();
        assert!(!after.authorized);
    }

    #[tokio::test]
    async fn an_honored_recheck_is_recorded_and_a_fresh_row_is_not_contacted() {
        let memory = Arc::new(MemoryStore::new());
        let stale = creator("pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy");
        let fresh = creator("pubkyorhzqdiexwmi6iidktucgud63ufa5nwtsuzdxe176a8izd6jsqky");
        let fresh_checked_at = OffsetDateTime::now_utc();
        memory.insert(authority(&stale, Some(hours_ago(7)), None));
        memory.insert(authority(&fresh, Some(fresh_checked_at), None));
        let revalidator = ScriptedRevalidator::honored();

        let report = revalidate_stale_creator_authorities(
            &StoreHandle(Arc::clone(&memory)),
            manager(Arc::clone(&memory), revalidator.clone()),
            &NowClock,
            policy(4, 1, 0),
        )
        .await
        .unwrap();

        assert_eq!(report.selected, 1);
        assert_eq!(report.honored, 1);
        assert_eq!(revalidator.seen(), 1);
        let fresh_validity = memory.validity(&fresh).unwrap();
        assert_eq!(fresh_validity.last_revalidated_at, Some(fresh_checked_at));
        assert!(fresh_validity.refused_at.is_none());
        let stale_validity = memory.validity(&stale).unwrap();
        assert!(stale_validity.last_revalidated_at.unwrap() > hours_ago(7));
        assert!(stale_validity.refused_at.is_none());
    }

    #[tokio::test]
    async fn an_unreachable_homeserver_leaves_the_stored_answer_in_place() {
        let memory = Arc::new(MemoryStore::new());
        let creator = creator("pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy");
        let checked_at = hours_ago(7);
        memory.insert(authority(&creator, Some(checked_at), None));

        let report = revalidate_stale_creator_authorities(
            &StoreHandle(Arc::clone(&memory)),
            manager(
                Arc::clone(&memory),
                ScriptedRevalidator::error(ApplicationError::CreatorAuthorityCheckUnavailable),
            ),
            &NowClock,
            policy(4, 1, 0),
        )
        .await
        .unwrap();

        assert_eq!(report.left_unchanged, 1);
        assert_eq!(report.refused, 0);
        let validity = memory.validity(&creator).unwrap();
        assert_eq!(validity.last_revalidated_at, Some(checked_at));
        assert!(validity.refused_at.is_none());
        assert!(validity.is_usable_at(OffsetDateTime::now_utc()));
    }

    #[tokio::test]
    async fn one_pass_contacts_only_the_configured_batch() {
        let memory = Arc::new(MemoryStore::new());
        for pubky in [
            "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy",
            "pubkyorhzqdiexwmi6iidktucgud63ufa5nwtsuzdxe176a8izd6jsqky",
            "pubky3kj4afafdba8diu5oxd96dz6orrqt5nfgbmi473go6ju8s64z36y",
        ] {
            let creator = creator(pubky);
            memory.insert(authority(&creator, None, None));
        }
        let revalidator = ScriptedRevalidator::refused();

        let first = revalidate_stale_creator_authorities(
            &StoreHandle(Arc::clone(&memory)),
            manager(Arc::clone(&memory), revalidator.clone()),
            &NowClock,
            policy(2, 1, 0),
        )
        .await
        .unwrap();
        assert_eq!(first.selected, 2);
        assert_eq!(first.refused, 2);
        assert_eq!(revalidator.seen(), 2);
        assert_eq!(memory.unchecked(), 1);

        let second = revalidate_stale_creator_authorities(
            &StoreHandle(Arc::clone(&memory)),
            manager(Arc::clone(&memory), revalidator.clone()),
            &NowClock,
            policy(2, 1, 0),
        )
        .await
        .unwrap();
        assert_eq!(second.selected, 1);
        assert_eq!(revalidator.seen(), 3);
        assert_eq!(memory.unchecked(), 0);
    }

    #[tokio::test]
    async fn checks_in_one_pass_do_not_run_together() {
        let memory = Arc::new(MemoryStore::new());
        for pubky in [
            "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy",
            "pubkyorhzqdiexwmi6iidktucgud63ufa5nwtsuzdxe176a8izd6jsqky",
        ] {
            memory.insert(authority(&creator(pubky), None, None));
        }
        let revalidator = GateRevalidator::new();

        let store = StoreHandle(Arc::clone(&memory));
        let pass_manager = manager(Arc::clone(&memory), revalidator.clone());
        let pass = tokio::spawn(async move {
            revalidate_stale_creator_authorities(&store, pass_manager, &NowClock, policy(4, 1, 0))
                .await
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            revalidator.entered.notified(),
        )
        .await
        .expect("first check starts");
        assert_eq!(revalidator.started.load(Ordering::SeqCst), 1);
        assert_eq!(revalidator.max_in_flight.load(Ordering::SeqCst), 1);

        revalidator.release.notify_one();
        let report = tokio::time::timeout(std::time::Duration::from_secs(2), pass)
            .await
            .expect("pass finishes after the first check is released")
            .unwrap()
            .unwrap();
        assert_eq!(report.refused, 2);
        assert_eq!(revalidator.max_in_flight.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_pass_waits_between_homeserver_checks() {
        let memory = Arc::new(MemoryStore::new());
        for pubky in [
            "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy",
            "pubkyorhzqdiexwmi6iidktucgud63ufa5nwtsuzdxe176a8izd6jsqky",
        ] {
            memory.insert(authority(&creator(pubky), None, None));
        }
        let started = tokio::time::Instant::now();

        revalidate_stale_creator_authorities(
            &StoreHandle(Arc::clone(&memory)),
            manager(Arc::clone(&memory), ScriptedRevalidator::refused()),
            &NowClock,
            policy(4, 1, 80),
        )
        .await
        .unwrap();

        assert!(started.elapsed() >= std::time::Duration::from_millis(50));
    }

    fn policy(batch_size: u32, concurrency: usize, stagger_ms: u64) -> AuthorityRevalidationPolicy {
        AuthorityRevalidationPolicy {
            stale_after: time::Duration::hours(6),
            batch_size,
            concurrency,
            stagger: std::time::Duration::from_millis(stagger_ms),
        }
    }

    fn manager(
        memory: Arc<MemoryStore>,
        revalidator: impl LegacyCookieSessionRevalidator + 'static,
    ) -> Arc<dyn CreatorAuthorityManager> {
        Arc::new(LegacyCookieCreatorAuthorityManager::new(
            StoreHandle(memory),
            revalidator,
        ))
    }

    fn creator(value: &str) -> CreatorPubky {
        CreatorPubky::from_str(value).unwrap()
    }

    fn hours_ago(hours: i64) -> OffsetDateTime {
        OffsetDateTime::now_utc() - time::Duration::hours(hours)
    }

    fn authority(
        creator: &CreatorPubky,
        last_revalidated_at: Option<OffsetDateTime>,
        refused_at: Option<OffsetDateTime>,
    ) -> (CreatorAuthorityRecord, Option<OffsetDateTime>) {
        (
            CreatorAuthorityRecord {
                creator: creator.clone(),
                auth_kind: CreatorAuthorityAuthKind::LegacyCookie,
                granted_scopes: vec!["/pub/locks.app/:rw".to_owned()],
                secret: CreatorAuthoritySecret::new(format!("secret-{creator}")),
                session_expires_at: Some(OffsetDateTime::now_utc() + time::Duration::days(1)),
                last_revalidated_at,
            },
            refused_at,
        )
    }

    struct NowClock;

    impl Clock for NowClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::now_utc()
        }
    }

    #[derive(Default)]
    struct MemoryStore {
        records: Mutex<Vec<(CreatorAuthorityRecord, Option<OffsetDateTime>)>>,
    }

    impl MemoryStore {
        fn new() -> Self {
            Self::default()
        }

        fn insert(&self, row: (CreatorAuthorityRecord, Option<OffsetDateTime>)) {
            self.records.lock().unwrap().push(row);
        }

        fn validity(&self, creator: &CreatorPubky) -> Option<CreatorAuthorityValidity> {
            self.records
                .lock()
                .unwrap()
                .iter()
                .find_map(|(record, refused_at)| {
                    (record.creator == *creator)
                        .then(|| CreatorAuthorityValidity::from_record(record, *refused_at))
                })
        }

        fn unchecked(&self) -> usize {
            self.records
                .lock()
                .unwrap()
                .iter()
                .filter(|(record, refused_at)| {
                    CreatorAuthorityValidity::from_record(record, *refused_at)
                        .last_checked_at()
                        .is_none()
                })
                .count()
        }
    }

    #[derive(Clone)]
    struct StoreHandle(Arc<MemoryStore>);

    impl StoreHandle {
        fn lookup(
            &self,
            store: &MemoryStore,
            creator: &CreatorPubky,
        ) -> Option<CreatorAuthorityValidity> {
            store
                .records
                .lock()
                .unwrap()
                .iter()
                .find_map(|(record, refused_at)| {
                    (record.creator == *creator)
                        .then(|| CreatorAuthorityValidity::from_record(record, *refused_at))
                })
        }
    }

    #[async_trait]
    impl CreatorAuthorityStore for StoreHandle {
        async fn upsert_creator_authority(
            &self,
            authority: CreatorAuthorityRecord,
        ) -> Result<(), ApplicationError> {
            let mut records = self.0.records.lock().unwrap();
            if let Some(existing) = records
                .iter_mut()
                .find(|(record, _)| record.creator == authority.creator)
            {
                *existing = (authority, None);
            } else {
                records.push((authority, None));
            }
            Ok(())
        }

        async fn get_creator_authority(
            &self,
            creator: &CreatorPubky,
        ) -> Result<Option<CreatorAuthorityRecord>, ApplicationError> {
            Ok(self
                .0
                .records
                .lock()
                .unwrap()
                .iter()
                .find(|(record, _)| record.creator == *creator)
                .map(|(record, _)| record.clone()))
        }

        async fn get_creator_authority_validity(
            &self,
            creator: &CreatorPubky,
        ) -> Result<Option<CreatorAuthorityValidity>, ApplicationError> {
            Ok(self.lookup(&self.0, creator))
        }

        async fn record_creator_authority_check(
            &self,
            creator: &CreatorPubky,
            outcome: CreatorAuthorityCheckOutcome,
            checked_at: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            let mut records = self.0.records.lock().unwrap();
            let Some(existing) = records
                .iter_mut()
                .find(|(record, _)| record.creator == *creator)
            else {
                return Ok(());
            };
            match outcome {
                CreatorAuthorityCheckOutcome::Honored => {
                    existing.0.last_revalidated_at = Some(checked_at);
                    existing.1 = None;
                }
                CreatorAuthorityCheckOutcome::Refused => existing.1 = Some(checked_at),
            }
            Ok(())
        }

        async fn list_creator_authorities_checked_before(
            &self,
            checked_before: OffsetDateTime,
            limit: u32,
        ) -> Result<Vec<CreatorPubky>, ApplicationError> {
            if limit == 0 {
                return Ok(Vec::new());
            }
            let mut due: Vec<(Option<OffsetDateTime>, CreatorPubky)> = self
                .0
                .records
                .lock()
                .unwrap()
                .iter()
                .filter_map(|(record, refused_at)| {
                    let validity = CreatorAuthorityValidity::from_record(record, *refused_at);
                    validity
                        .due_before(checked_before)
                        .then(|| (validity.last_checked_at(), record.creator.clone()))
                })
                .collect();
            due.sort_by(|left, right| {
                left.0
                    .cmp(&right.0)
                    .then_with(|| left.1.to_string().cmp(&right.1.to_string()))
            });
            Ok(due
                .into_iter()
                .take(usize::try_from(limit).unwrap_or(usize::MAX))
                .map(|(_, creator)| creator)
                .collect())
        }

        async fn delete_creator_authority(
            &self,
            creator: &CreatorPubky,
        ) -> Result<(), ApplicationError> {
            self.0
                .records
                .lock()
                .unwrap()
                .retain(|(record, _)| record.creator != *creator);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct ScriptedRevalidator {
        result: Result<(), ApplicationError>,
        seen: Arc<AtomicUsize>,
    }

    impl ScriptedRevalidator {
        fn honored() -> Self {
            Self::error_or(Ok(()))
        }

        fn refused() -> Self {
            Self::error(ApplicationError::CreatorAuthorityRefused)
        }

        fn error(error: ApplicationError) -> Self {
            Self::error_or(Err(error))
        }

        fn error_or(result: Result<(), ApplicationError>) -> Self {
            Self {
                result,
                seen: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn seen(&self) -> usize {
            self.seen.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl LegacyCookieSessionRevalidator for ScriptedRevalidator {
        async fn revalidate_legacy_cookie_secret(
            &self,
            _secret: &CreatorAuthoritySecret,
        ) -> Result<(), ApplicationError> {
            self.seen.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }
    }

    #[derive(Clone)]
    struct GateRevalidator {
        started: Arc<AtomicUsize>,
        in_flight: Arc<AtomicUsize>,
        max_in_flight: Arc<AtomicUsize>,
        release: Arc<Notify>,
        entered: Arc<Notify>,
    }

    impl GateRevalidator {
        fn new() -> Self {
            Self {
                started: Arc::new(AtomicUsize::new(0)),
                in_flight: Arc::new(AtomicUsize::new(0)),
                max_in_flight: Arc::new(AtomicUsize::new(0)),
                release: Arc::new(Notify::new()),
                entered: Arc::new(Notify::new()),
            }
        }
    }

    #[async_trait]
    impl LegacyCookieSessionRevalidator for GateRevalidator {
        async fn revalidate_legacy_cookie_secret(
            &self,
            _secret: &CreatorAuthoritySecret,
        ) -> Result<(), ApplicationError> {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
            let ordinal = self.started.fetch_add(1, Ordering::SeqCst) + 1;
            self.entered.notify_one();
            if ordinal == 1 {
                self.release.notified().await;
            }
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Err(ApplicationError::CreatorAuthorityRefused)
        }
    }
}
