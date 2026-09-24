use async_trait::async_trait;
use time::OffsetDateTime;

use locks_core::ids::CreatorPubky;

use crate::application::errors::ApplicationError;
use crate::application::models::{
    CreatorAuthorityAuthKind, CreatorAuthorityCheckOutcome, CreatorAuthorityRecord,
    CreatorAuthoritySecret,
};
use crate::application::ports::{
    CreatorAuthorityManager, CreatorAuthorityStatus, CreatorAuthorityStore,
};
use crate::infrastructure::pubky::grant_connect_flow::{
    LockServerGrantPopKeys, restore_grant_session_for_creator,
};

/// Revalidates a stored legacy Pubky cookie-session secret.
#[async_trait]
pub trait LegacyCookieSessionRevalidator: Send + Sync {
    /// Restores and validates a legacy cookie-session secret.
    async fn revalidate_legacy_cookie_secret(
        &self,
        secret: &CreatorAuthoritySecret,
    ) -> Result<(), ApplicationError>;
}

/// Pubky SDK-backed legacy cookie-session revalidator.
#[derive(Debug, Clone)]
pub struct PubkyLegacyCookieSessionRevalidator {
    client: pubky::PubkyHttpClient,
}

impl PubkyLegacyCookieSessionRevalidator {
    /// Creates a revalidator backed by the provided Pubky HTTP client.
    pub fn new(client: pubky::PubkyHttpClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl LegacyCookieSessionRevalidator for PubkyLegacyCookieSessionRevalidator {
    async fn revalidate_legacy_cookie_secret(
        &self,
        secret: &CreatorAuthoritySecret,
    ) -> Result<(), ApplicationError> {
        pubky::PubkySession::import_secret(secret.expose_secret(), Some(self.client.clone()))
            .await
            .map(|_| ())
            .map_err(|error| {
                classify_homeserver_restore_error(&error, || {
                    ApplicationError::CreatorAuthoritySecret {
                        message: "failed to restore legacy creator authority secret".to_owned(),
                    }
                })
            })
    }
}

/// Maps a Pubky SDK restore failure to what it says about the stored authority.
///
/// - 401, 403, 404, or 410 from the homeserver: the authority was refused (revoked, expired,
///   or unknown there), so [`ApplicationError::CreatorAuthorityRefused`].
/// - Transport failure, 408, 429, 5xx, or DHT resolution: nothing is known about the
///   authority, so [`ApplicationError::CreatorAuthorityCheckUnavailable`].
/// - Anything else (local parse, auth-token, or build failure): `local()`, a secret error
///   that callers surface instead of recording.
pub fn classify_homeserver_restore_error(
    error: &pubky::Error,
    local: impl FnOnce() -> ApplicationError,
) -> ApplicationError {
    use pubky::StatusCode;
    use pubky::errors::RequestError;

    match error {
        pubky::Error::Request(RequestError::Server { status, .. }) => match *status {
            StatusCode::UNAUTHORIZED
            | StatusCode::FORBIDDEN
            | StatusCode::NOT_FOUND
            | StatusCode::GONE => ApplicationError::CreatorAuthorityRefused,
            StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS => {
                ApplicationError::CreatorAuthorityCheckUnavailable
            }
            status if status.is_server_error() => {
                ApplicationError::CreatorAuthorityCheckUnavailable
            }
            _ => local(),
        },
        pubky::Error::Request(RequestError::Transport(_)) | pubky::Error::Pkarr(_) => {
            ApplicationError::CreatorAuthorityCheckUnavailable
        }
        _ => local(),
    }
}

/// Revalidates stored delegated grant restore state.
#[async_trait]
pub trait GrantCredentialRevalidator: Send + Sync {
    /// Restores the grant for `creator` and fails unless its session belongs to `creator`.
    async fn revalidate_grant_credential(
        &self,
        creator: &CreatorPubky,
        secret: &CreatorAuthoritySecret,
    ) -> Result<(), ApplicationError>;
}

/// Refuses every grant record. Used where the Lock Server grant PoP keys are unavailable.
#[derive(Debug, Clone, Copy, Default)]
pub struct GrantAuthorityUnavailable;

#[async_trait]
impl GrantCredentialRevalidator for GrantAuthorityUnavailable {
    async fn revalidate_grant_credential(
        &self,
        _creator: &CreatorPubky,
        _secret: &CreatorAuthoritySecret,
    ) -> Result<(), ApplicationError> {
        Err(ApplicationError::CreatorAuthorityUnavailable)
    }
}

/// Pubky SDK-backed grant revalidator using `GrantCredential::import_delegated_state`.
#[derive(Debug, Clone)]
pub struct PubkyGrantCredentialRevalidator {
    client: pubky::PubkyHttpClient,
    pop_keys: LockServerGrantPopKeys,
}

impl PubkyGrantCredentialRevalidator {
    /// Creates a revalidator backed by the Pubky HTTP client and Lock Server grant PoP keys.
    pub fn new(client: pubky::PubkyHttpClient, pop_keys: LockServerGrantPopKeys) -> Self {
        Self { client, pop_keys }
    }
}

#[async_trait]
impl GrantCredentialRevalidator for PubkyGrantCredentialRevalidator {
    async fn revalidate_grant_credential(
        &self,
        creator: &CreatorPubky,
        secret: &CreatorAuthoritySecret,
    ) -> Result<(), ApplicationError> {
        restore_grant_session_for_creator(&self.client, &self.pop_keys, creator, secret)
            .await
            .map(|_| ())
    }
}

/// Creator authority manager for Pubky creator authority: legacy cookie records and, when a
/// grant revalidator is attached, grant records.
#[derive(Debug)]
pub struct LegacyCookieCreatorAuthorityManager<S, R, G = GrantAuthorityUnavailable> {
    store: S,
    revalidator: R,
    grant_revalidator: G,
}

impl<S, R> LegacyCookieCreatorAuthorityManager<S, R> {
    /// Creates a manager from a creator authority store and legacy cookie revalidator.
    /// Grant records are refused until [`Self::with_grant_revalidator`] attaches one.
    pub fn new(store: S, revalidator: R) -> Self {
        Self {
            store,
            revalidator,
            grant_revalidator: GrantAuthorityUnavailable,
        }
    }
}

impl<S, R, G> LegacyCookieCreatorAuthorityManager<S, R, G> {
    /// Attaches the revalidator used for `Grant` records.
    pub fn with_grant_revalidator<G2>(
        self,
        grant_revalidator: G2,
    ) -> LegacyCookieCreatorAuthorityManager<S, R, G2> {
        LegacyCookieCreatorAuthorityManager {
            store: self.store,
            revalidator: self.revalidator,
            grant_revalidator,
        }
    }

    /// Returns the creator authority store. Exposed for tests and adapter composition.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Returns the revalidator. Exposed for tests and adapter composition.
    pub fn revalidator(&self) -> &R {
        &self.revalidator
    }

    /// Returns the grant revalidator. Exposed for tests and adapter composition.
    pub fn grant_revalidator(&self) -> &G {
        &self.grant_revalidator
    }
}

#[async_trait]
impl<S, R, G> CreatorAuthorityManager for LegacyCookieCreatorAuthorityManager<S, R, G>
where
    S: CreatorAuthorityStore,
    R: LegacyCookieSessionRevalidator,
    G: GrantCredentialRevalidator,
{
    async fn revalidate_creator_authority(
        &self,
        creator: &CreatorPubky,
    ) -> Result<CreatorAuthorityStatus, ApplicationError> {
        let record = self
            .store
            .get_creator_authority(creator)
            .await?
            .ok_or(ApplicationError::CreatorAuthorityUnavailable)?;

        let checked = match record.auth_kind {
            CreatorAuthorityAuthKind::LegacyCookie => {
                self.revalidator
                    .revalidate_legacy_cookie_secret(&record.secret)
                    .await
            }
            CreatorAuthorityAuthKind::Grant => {
                self.grant_revalidator
                    .revalidate_grant_credential(creator, &record.secret)
                    .await
            }
        };

        // Only the homeserver's own answer is recorded. Transport failures and local secret
        // errors say nothing about the authority, so they leave the stored validity alone.
        let outcome = match &checked {
            Ok(()) => Some(CreatorAuthorityCheckOutcome::Honored),
            Err(ApplicationError::CreatorAuthorityRefused) => {
                Some(CreatorAuthorityCheckOutcome::Refused)
            }
            Err(_) => None,
        };
        if let Some(outcome) = outcome {
            self.store
                .record_creator_authority_check(creator, outcome, OffsetDateTime::now_utc())
                .await?;
        }
        checked?;

        Ok(record_to_authorized_status(record))
    }

    async fn require_creator_authority(
        &self,
        creator: &CreatorPubky,
    ) -> Result<CreatorAuthorityStatus, ApplicationError> {
        self.revalidate_creator_authority(creator).await
    }
}

fn record_to_authorized_status(record: CreatorAuthorityRecord) -> CreatorAuthorityStatus {
    CreatorAuthorityStatus {
        creator: record.creator,
        auth_kind: record.auth_kind,
        authorized: true,
        granted_scopes: record.granted_scopes,
        session_expires_at: record.session_expires_at,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use locks_core::ids::CreatorPubky;
    use time::macros::datetime;

    use super::{
        GrantCredentialRevalidator, LegacyCookieCreatorAuthorityManager,
        LegacyCookieSessionRevalidator, classify_homeserver_restore_error,
    };
    use crate::application::errors::ApplicationError;
    use crate::application::models::{
        CreatorAuthorityAuthKind, CreatorAuthorityCheckOutcome, CreatorAuthorityRecord,
        CreatorAuthoritySecret, CreatorAuthorityValidity,
    };
    use crate::application::ports::{
        CreatorAuthorityManager, CreatorAuthorityStatus, CreatorAuthorityStore,
    };

    #[tokio::test]
    async fn missing_authority_returns_unavailable_without_revalidating() {
        let store = FakeCreatorAuthorityStore::new(None);
        let revalidator = FakeLegacyCookieSessionRevalidator::new(Ok(()));
        let manager = LegacyCookieCreatorAuthorityManager::new(store, revalidator);

        assert_eq!(
            manager.require_creator_authority(&creator()).await,
            Err(ApplicationError::CreatorAuthorityUnavailable)
        );
        assert_eq!(manager.revalidator().seen_secrets(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn grant_record_without_grant_revalidator_returns_unavailable_without_revalidating() {
        let store = FakeCreatorAuthorityStore::new(Some(CreatorAuthorityRecord {
            auth_kind: CreatorAuthorityAuthKind::Grant,
            ..creator_authority_record("grant-credential-secret")
        }));
        let revalidator = FakeLegacyCookieSessionRevalidator::new(Ok(()));
        let manager = LegacyCookieCreatorAuthorityManager::new(store, revalidator);

        assert_eq!(
            manager.require_creator_authority(&creator()).await,
            Err(ApplicationError::CreatorAuthorityUnavailable)
        );
        assert_eq!(manager.revalidator().seen_secrets(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn grant_record_revalidates_through_grant_revalidator_not_cookie_slot() {
        let store = FakeCreatorAuthorityStore::new(Some(CreatorAuthorityRecord {
            auth_kind: CreatorAuthorityAuthKind::Grant,
            ..creator_authority_record("grant-restore-state")
        }));
        let manager = LegacyCookieCreatorAuthorityManager::new(
            store,
            FakeLegacyCookieSessionRevalidator::new(Ok(())),
        )
        .with_grant_revalidator(FakeGrantRevalidator::new(Ok(())));

        let status = manager.require_creator_authority(&creator()).await.unwrap();

        assert_eq!(status.auth_kind, CreatorAuthorityAuthKind::Grant);
        assert!(status.authorized);
        assert_eq!(manager.revalidator().seen_secrets(), Vec::<String>::new());
        assert_eq!(
            manager.grant_revalidator().seen(),
            vec![(creator(), "grant-restore-state".to_owned())]
        );
        assert!(!format!("{status:?}").contains("grant-restore-state"));
    }

    #[tokio::test]
    async fn failed_grant_revalidation_returns_error_without_leaking_state() {
        let store = FakeCreatorAuthorityStore::new(Some(CreatorAuthorityRecord {
            auth_kind: CreatorAuthorityAuthKind::Grant,
            ..creator_authority_record("grant-restore-state")
        }));
        let manager = LegacyCookieCreatorAuthorityManager::new(
            store,
            FakeLegacyCookieSessionRevalidator::new(Ok(())),
        )
        .with_grant_revalidator(FakeGrantRevalidator::new(Err(
            ApplicationError::CreatorAuthorityUnavailable,
        )));

        let error = manager
            .require_creator_authority(&creator())
            .await
            .unwrap_err();

        assert_eq!(error, ApplicationError::CreatorAuthorityUnavailable);
        assert!(!format!("{error:?}").contains("grant-restore-state"));
    }

    #[tokio::test]
    async fn valid_legacy_record_revalidates_secret_and_returns_secret_free_status() {
        let record = creator_authority_record("legacy-cookie-session-secret");
        let store = FakeCreatorAuthorityStore::new(Some(record));
        let revalidator = FakeLegacyCookieSessionRevalidator::new(Ok(()));
        let manager = LegacyCookieCreatorAuthorityManager::new(store, revalidator);

        let status = manager.require_creator_authority(&creator()).await.unwrap();

        assert_eq!(
            status,
            CreatorAuthorityStatus {
                creator: creator(),
                auth_kind: CreatorAuthorityAuthKind::LegacyCookie,
                authorized: true,
                granted_scopes: vec![
                    "/pub/locks.app/:rw".to_owned(),
                    "/priv/locks.app/:rw".to_owned(),
                ],
                session_expires_at: Some(datetime!(2026-05-29 12:15:00 UTC)),
            }
        );
        assert_eq!(
            manager.revalidator().seen_secrets(),
            vec!["legacy-cookie-session-secret".to_owned()]
        );
        assert!(!format!("{status:?}").contains("legacy-cookie-session-secret"));
    }

    #[tokio::test]
    async fn failed_legacy_revalidation_returns_unavailable_without_leaking_secret() {
        let store = FakeCreatorAuthorityStore::new(Some(creator_authority_record(
            "legacy-cookie-session-secret",
        )));
        let revalidator = FakeLegacyCookieSessionRevalidator::new(Err(
            ApplicationError::CreatorAuthorityUnavailable,
        ));
        let manager = LegacyCookieCreatorAuthorityManager::new(store, revalidator);

        let error = manager
            .require_creator_authority(&creator())
            .await
            .unwrap_err();

        assert_eq!(error, ApplicationError::CreatorAuthorityUnavailable);
        assert!(!format!("{error:?}").contains("legacy-cookie-session-secret"));
    }

    #[tokio::test]
    async fn manager_records_the_homeserver_answer_but_never_an_unreachable_one() {
        for (answer, recorded) in [
            (Ok(()), vec![CreatorAuthorityCheckOutcome::Honored]),
            (
                Err(ApplicationError::CreatorAuthorityRefused),
                vec![CreatorAuthorityCheckOutcome::Refused],
            ),
            (
                Err(ApplicationError::CreatorAuthorityCheckUnavailable),
                vec![],
            ),
            (
                Err(ApplicationError::CreatorAuthoritySecret {
                    message: "failed to restore legacy creator authority secret".to_owned(),
                }),
                vec![],
            ),
        ] {
            let expected_error = answer.clone().err();
            let manager = LegacyCookieCreatorAuthorityManager::new(
                FakeCreatorAuthorityStore::new(Some(creator_authority_record(
                    "legacy-cookie-session-secret",
                ))),
                FakeLegacyCookieSessionRevalidator::new(answer),
            );

            let result = manager.require_creator_authority(&creator()).await;

            assert_eq!(result.err(), expected_error);
            assert_eq!(*manager.store().checks.lock().unwrap(), recorded);
        }
    }

    #[test]
    fn homeserver_status_classifies_refusal_apart_from_an_unreachable_homeserver() {
        use pubky::StatusCode;
        use pubky::errors::{AuthError, RequestError};

        let server = |status: StatusCode| {
            pubky::Error::Request(RequestError::Server {
                status,
                message: String::new(),
            })
        };
        let local = || ApplicationError::CreatorAuthoritySecret {
            message: "local".to_owned(),
        };

        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::GONE,
        ] {
            assert_eq!(
                classify_homeserver_restore_error(&server(status), local),
                ApplicationError::CreatorAuthorityRefused,
                "{status}"
            );
        }
        for status in [
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert_eq!(
                classify_homeserver_restore_error(&server(status), local),
                ApplicationError::CreatorAuthorityCheckUnavailable,
                "{status}"
            );
        }
        assert_eq!(
            classify_homeserver_restore_error(&server(StatusCode::BAD_REQUEST), local),
            local()
        );
        assert_eq!(
            classify_homeserver_restore_error(
                &pubky::Error::Authentication(AuthError::RequestExpired),
                local
            ),
            local()
        );
    }

    #[derive(Debug)]
    struct FakeCreatorAuthorityStore {
        record: Option<CreatorAuthorityRecord>,
        checks: Mutex<Vec<CreatorAuthorityCheckOutcome>>,
    }

    impl FakeCreatorAuthorityStore {
        fn new(record: Option<CreatorAuthorityRecord>) -> Self {
            Self {
                record,
                checks: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl CreatorAuthorityStore for FakeCreatorAuthorityStore {
        async fn upsert_creator_authority(
            &self,
            _authority: CreatorAuthorityRecord,
        ) -> Result<(), ApplicationError> {
            unimplemented!("not needed by manager tests")
        }

        async fn get_creator_authority(
            &self,
            creator: &CreatorPubky,
        ) -> Result<Option<CreatorAuthorityRecord>, ApplicationError> {
            Ok(self
                .record
                .as_ref()
                .filter(|record| &record.creator == creator)
                .cloned())
        }

        async fn get_creator_authority_validity(
            &self,
            creator: &CreatorPubky,
        ) -> Result<Option<CreatorAuthorityValidity>, ApplicationError> {
            Ok(self
                .record
                .as_ref()
                .filter(|record| &record.creator == creator)
                .map(|record| CreatorAuthorityValidity::from_record(record, None)))
        }

        async fn record_creator_authority_check(
            &self,
            _creator: &CreatorPubky,
            outcome: CreatorAuthorityCheckOutcome,
            _checked_at: time::OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            self.checks.lock().unwrap().push(outcome);
            Ok(())
        }

        async fn delete_creator_authority(
            &self,
            _creator: &CreatorPubky,
        ) -> Result<(), ApplicationError> {
            unimplemented!("not needed by manager tests")
        }
    }

    #[derive(Debug)]
    struct FakeLegacyCookieSessionRevalidator {
        result: Result<(), ApplicationError>,
        seen_secrets: Mutex<Vec<String>>,
    }

    impl FakeLegacyCookieSessionRevalidator {
        fn new(result: Result<(), ApplicationError>) -> Self {
            Self {
                result,
                seen_secrets: Mutex::new(Vec::new()),
            }
        }

        fn seen_secrets(&self) -> Vec<String> {
            self.seen_secrets.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl LegacyCookieSessionRevalidator for FakeLegacyCookieSessionRevalidator {
        async fn revalidate_legacy_cookie_secret(
            &self,
            secret: &CreatorAuthoritySecret,
        ) -> Result<(), ApplicationError> {
            self.seen_secrets
                .lock()
                .unwrap()
                .push(secret.expose_secret().to_owned());
            self.result.clone()
        }
    }

    #[derive(Debug)]
    struct FakeGrantRevalidator {
        result: Result<(), ApplicationError>,
        seen: Mutex<Vec<(CreatorPubky, String)>>,
    }

    impl FakeGrantRevalidator {
        fn new(result: Result<(), ApplicationError>) -> Self {
            Self {
                result,
                seen: Mutex::new(Vec::new()),
            }
        }

        fn seen(&self) -> Vec<(CreatorPubky, String)> {
            self.seen.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl GrantCredentialRevalidator for FakeGrantRevalidator {
        async fn revalidate_grant_credential(
            &self,
            creator: &CreatorPubky,
            secret: &CreatorAuthoritySecret,
        ) -> Result<(), ApplicationError> {
            self.seen
                .lock()
                .unwrap()
                .push((creator.clone(), secret.expose_secret().to_owned()));
            self.result.clone()
        }
    }

    fn creator_authority_record(secret: &str) -> CreatorAuthorityRecord {
        CreatorAuthorityRecord {
            creator: creator(),
            auth_kind: CreatorAuthorityAuthKind::LegacyCookie,
            granted_scopes: vec![
                "/pub/locks.app/:rw".to_owned(),
                "/priv/locks.app/:rw".to_owned(),
            ],
            secret: CreatorAuthoritySecret::new(secret),
            session_expires_at: Some(datetime!(2026-05-29 12:15:00 UTC)),
            last_revalidated_at: Some(datetime!(2026-05-29 12:00:00 UTC)),
        }
    }

    fn creator() -> CreatorPubky {
        CreatorPubky::from_str("pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy").unwrap()
    }
}
