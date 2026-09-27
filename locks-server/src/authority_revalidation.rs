use std::sync::Arc;
use std::time::Duration;

use locks_service::application::errors::ApplicationError;
use locks_service::application::ports::{Clock, CreatorAuthorityManager, CreatorAuthorityStore};
use locks_service::application::use_cases::revalidate_stale_creator_authorities::{
    AuthorityRevalidationPolicy, AuthorityRevalidationReport,
    revalidate_stale_creator_authorities_once,
};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::app_state::AppState;
use crate::config::AuthorityRevalidationConfig;

/// Periodically rechecks creator authorities whose last real check is older than the
/// configured age. Each check is the manager's real revalidation, so a homeserver refusal
/// or honor is recorded the same way as a content or payment request.
pub struct AuthorityRevalidationWorker<'a> {
    store: &'a dyn CreatorAuthorityStore,
    manager: Arc<dyn CreatorAuthorityManager>,
    clock: &'a dyn Clock,
    policy: AuthorityRevalidationPolicy,
    poll_interval: Duration,
}

impl<'a> AuthorityRevalidationWorker<'a> {
    pub fn from_state(state: &'a AppState) -> Self {
        let config = &state.config().authority_revalidation;
        Self {
            store: state.creator_authorities().as_ref(),
            manager: Arc::clone(state.creator_authority_manager()),
            clock: state.clock().as_ref(),
            policy: policy_from_config(config),
            poll_interval: Duration::from_secs(config.poll_interval_seconds),
        }
    }

    pub async fn run_once(&self) -> Result<AuthorityRevalidationReport, ApplicationError> {
        let report = revalidate_stale_creator_authorities_once(
            self.store,
            Arc::clone(&self.manager),
            self.clock,
            self.policy,
        )
        .await?;
        if report.selected > 0 {
            info!(
                selected = report.selected,
                honored = report.honored,
                refused = report.refused,
                left_unchanged = report.left_unchanged,
                "revalidated stale creator authorities"
            );
        }
        Ok(report)
    }

    pub async fn run_until_shutdown(
        &self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), ApplicationError> {
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            if let Err(error) = self.run_once().await {
                warn!(%error, "creator authority revalidation pass failed");
            }
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return Ok(());
                    }
                }
                _ = tokio::time::sleep(self.poll_interval) => {}
            }
        }
    }
}

/// Largest hour count `time::Duration::hours` can build without panicking.
pub const MAX_REPRESENTABLE_HOURS: u64 = (i64::MAX / 3_600) as u64;

pub fn duration_from_hours(hours: u64) -> time::Duration {
    let hours = i64::try_from(hours)
        .unwrap_or(i64::MAX / 3_600)
        .min(i64::MAX / 3_600);
    time::Duration::hours(hours)
}

fn duration_from_seconds(seconds: u64) -> time::Duration {
    let seconds = i64::try_from(seconds).unwrap_or(i64::MAX);
    time::Duration::seconds(seconds)
}

fn policy_from_config(config: &AuthorityRevalidationConfig) -> AuthorityRevalidationPolicy {
    AuthorityRevalidationPolicy {
        stale_after: duration_from_hours(config.stale_after_hours),
        batch_size: config.batch_size,
        concurrency: usize::try_from(config.concurrency)
            .unwrap_or(usize::MAX)
            .max(1),
        stagger: Duration::from_millis(config.stagger_ms),
        retry_base: duration_from_seconds(config.retry_base_seconds),
        retry_cap: duration_from_hours(config.retry_cap_hours),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use locks_core::ids::CreatorPubky;
    use locks_service::application::models::{
        CreatorAuthorityAuthKind, CreatorAuthorityRecord, CreatorAuthoritySecret,
    };
    use time::OffsetDateTime;

    use super::{
        AuthorityRevalidationWorker, MAX_REPRESENTABLE_HOURS, duration_from_hours,
        policy_from_config,
    };
    use crate::app_state::AppState;
    use crate::config::AuthorityRevalidationConfig;
    use crate::testing::TestServerApp;

    #[tokio::test]
    async fn one_pass_rechecks_a_stale_authority_and_skips_a_fresh_one() {
        let state = AppState::new_empty_in_memory(TestServerApp::default_in_memory_config());
        let stale = creator("pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy");
        let fresh = creator("pubkyorhzqdiexwmi6iidktucgud63ufa5nwtsuzdxe176a8izd6jsqky");
        let stale_checked_at = OffsetDateTime::now_utc() - time::Duration::hours(7);
        let fresh_checked_at = OffsetDateTime::now_utc();
        state
            .creator_authorities()
            .upsert_creator_authority(record(&stale, Some(stale_checked_at)))
            .await
            .unwrap();
        state
            .creator_authorities()
            .upsert_creator_authority(record(&fresh, Some(fresh_checked_at)))
            .await
            .unwrap();

        let report = AuthorityRevalidationWorker::from_state(&state)
            .run_once()
            .await
            .unwrap();

        assert_eq!(report.selected, 1);
        assert_eq!(report.honored, 1);
        let stale_validity = state
            .creator_authorities()
            .get_creator_authority_validity(&stale)
            .await
            .unwrap()
            .unwrap();
        assert!(stale_validity.last_revalidated_at.unwrap() > stale_checked_at);
        let fresh_validity = state
            .creator_authorities()
            .get_creator_authority_validity(&fresh)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fresh_validity.last_revalidated_at, Some(fresh_checked_at));
    }

    #[test]
    fn a_huge_stale_after_does_not_panic() {
        let config = AuthorityRevalidationConfig {
            stale_after_hours: u64::MAX,
            retry_cap_hours: u64::MAX,
            retry_base_seconds: u64::MAX,
            ..AuthorityRevalidationConfig::default()
        };
        let policy = policy_from_config(&config);
        assert_eq!(policy.stale_after, duration_from_hours(u64::MAX));
        assert!(policy.retry_cap <= duration_from_hours(MAX_REPRESENTABLE_HOURS));
    }

    fn creator(value: &str) -> CreatorPubky {
        CreatorPubky::from_str(value).unwrap()
    }

    fn record(
        creator: &CreatorPubky,
        last_revalidated_at: Option<OffsetDateTime>,
    ) -> CreatorAuthorityRecord {
        CreatorAuthorityRecord {
            creator: creator.clone(),
            auth_kind: CreatorAuthorityAuthKind::LegacyCookie,
            granted_scopes: vec!["/pub/locks.app/:rw".to_owned()],
            secret: CreatorAuthoritySecret::new("legacy-cookie-session-secret"),
            session_expires_at: Some(OffsetDateTime::now_utc() + time::Duration::days(1)),
            last_revalidated_at,
        }
    }
}
