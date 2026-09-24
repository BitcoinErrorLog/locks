use time::OffsetDateTime;

use locks_core::ids::CreatorPubky;

use crate::application::errors::ApplicationError;
use crate::application::models::{CreatorAuthorityAuthKind, FrontendSessionToken};
use crate::application::ports::{
    Clock, CreatorAuthorityManager, CreatorAuthorityStore, FrontendSessionStore,
};

/// Request for secret-free creator authority status from authenticated frontend context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetCreatorAuthorityStatusRequest {
    /// Raw frontend session bearer token supplied by pubky.app/browser code.
    pub session_token: FrontendSessionToken,
}

/// Secret-free view of creator-granted homeserver authority for creator UI/status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatorAuthorityStatusView {
    /// Creator identity derived from the Locks-local frontend session.
    pub creator: CreatorPubky,
    /// Whether this Lock Server currently has stored creator authority.
    pub authorized: bool,
    /// Auth mechanism backing the stored authority, when present.
    pub auth_kind: Option<CreatorAuthorityAuthKind>,
    /// Scopes granted to the Lock Server, when authority is present.
    pub granted_scopes: Vec<String>,
    /// Optional session expiration reported by the underlying auth mechanism.
    pub session_expires_at: Option<OffsetDateTime>,
}

/// Returns secret-free creator authority status for an authenticated frontend session.
pub async fn get_creator_authority_status(
    frontend_sessions: &dyn FrontendSessionStore,
    creator_authorities: &dyn CreatorAuthorityStore,
    clock: &dyn Clock,
    request: GetCreatorAuthorityStatusRequest,
) -> Result<CreatorAuthorityStatusView, ApplicationError> {
    let now = clock.now();
    let Some(frontend_session) = frontend_sessions
        .get_frontend_session(&request.session_token)
        .await?
    else {
        return Err(ApplicationError::FrontendSessionUnavailable);
    };

    if frontend_session.is_expired_at(now) {
        return Err(ApplicationError::FrontendSessionExpired);
    }

    let creator = frontend_session.creator;
    let Some(authority) = creator_authorities.get_creator_authority(&creator).await? else {
        return Ok(CreatorAuthorityStatusView {
            creator,
            authorized: false,
            auth_kind: None,
            granted_scopes: Vec::new(),
            session_expires_at: None,
        });
    };

    Ok(CreatorAuthorityStatusView {
        creator,
        authorized: true,
        auth_kind: Some(authority.auth_kind),
        granted_scopes: authority.granted_scopes,
        session_expires_at: authority.session_expires_at,
    })
}

/// Creator-keyed status that carries no session, auth kind, scopes, or expiry.
///
/// Callers learn only whether this Lock Server can use creator authority for `creator`
/// right now, so a seller UI can show the connection after its frontend session has
/// expired or its browser storage was cleared, without asking the creator to approve again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicCreatorAuthorityStatusView {
    /// Creator identity from the request path, in canonical form.
    pub creator: CreatorPubky,
    /// Whether the stored authority passes the same revalidation the Lock Server runs
    /// before Pubky homeserver I/O.
    pub authorized: bool,
}

/// Returns whether this Lock Server holds usable creator authority, without a frontend session.
///
/// Usable means exactly what [`CreatorAuthorityManager::require_creator_authority`] accepts
/// before content, entitlement, and payment-path homeserver I/O: a stored record whose
/// cookie session or grant the creator's homeserver still honors. A missing, revoked,
/// expired, or unrestorable record reports `authorized: false`. Storage and other internal
/// failures are errors, not `false`.
pub async fn get_public_creator_authority_status(
    creator_authority_manager: &dyn CreatorAuthorityManager,
    creator: CreatorPubky,
) -> Result<PublicCreatorAuthorityStatusView, ApplicationError> {
    let authorized = match creator_authority_manager
        .require_creator_authority(&creator)
        .await
    {
        Ok(status) => status.authorized && status.creator == creator,
        Err(
            ApplicationError::CreatorAuthorityUnavailable
            | ApplicationError::CreatorAuthoritySecret { .. },
        ) => false,
        Err(error) => return Err(error),
    };
    Ok(PublicCreatorAuthorityStatusView {
        creator,
        authorized,
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use locks_core::ids::CreatorPubky;
    use time::{Duration, OffsetDateTime};

    use super::{
        GetCreatorAuthorityStatusRequest, get_creator_authority_status,
        get_public_creator_authority_status,
    };
    use crate::application::errors::ApplicationError;
    use crate::application::models::{
        CreatorAuthorityAuthKind, CreatorAuthorityRecord, CreatorAuthoritySecret,
        FrontendSessionRecord, FrontendSessionToken,
    };
    use crate::application::ports::{
        Clock, CreatorAuthorityManager, CreatorAuthorityStore, FrontendSessionStore,
    };
    use crate::infrastructure::pubky::legacy_creator_authority::{
        GrantCredentialRevalidator, LegacyCookieCreatorAuthorityManager,
        LegacyCookieSessionRevalidator,
    };

    #[tokio::test]
    async fn get_creator_authority_status_returns_unauthorized_when_frontend_session_is_missing_or_expired()
     {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

        let missing = get_creator_authority_status(
            &SessionStore::default(),
            &AuthorityStore::default(),
            &FixedClock(now),
            GetCreatorAuthorityStatusRequest {
                session_token: FrontendSessionToken::new("missing-token"),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(missing, ApplicationError::FrontendSessionUnavailable);

        let expired = get_creator_authority_status(
            &SessionStore::with_record(FrontendSessionRecord {
                expires_at: now,
                ..session_record(now - Duration::hours(12))
            }),
            &AuthorityStore::default(),
            &FixedClock(now),
            GetCreatorAuthorityStatusRequest {
                session_token: FrontendSessionToken::new("expired-token"),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(expired, ApplicationError::FrontendSessionExpired);
    }

    #[tokio::test]
    async fn get_creator_authority_status_returns_missing_when_creator_authority_record_is_absent()
    {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

        let status = get_creator_authority_status(
            &SessionStore::with_record(session_record(now)),
            &AuthorityStore::default(),
            &FixedClock(now),
            GetCreatorAuthorityStatusRequest {
                session_token: FrontendSessionToken::new("frontend-session-token"),
            },
        )
        .await
        .unwrap();

        assert_eq!(status.creator, creator());
        assert!(!status.authorized);
        assert_eq!(status.auth_kind, None);
        assert!(status.granted_scopes.is_empty());
        assert_eq!(status.session_expires_at, None);
    }

    #[tokio::test]
    async fn get_creator_authority_status_returns_secret_free_authorized_status_when_record_exists()
    {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let session_expires_at = now + Duration::days(30);
        let authority = CreatorAuthorityRecord {
            creator: creator(),
            auth_kind: CreatorAuthorityAuthKind::LegacyCookie,
            granted_scopes: vec![
                "/pub/locks.app/:rw".to_owned(),
                "/priv/locks.app/:rw".to_owned(),
            ],
            secret: CreatorAuthoritySecret::new("creator-authority-secret"),
            session_expires_at: Some(session_expires_at),
            last_revalidated_at: None,
        };

        let status = get_creator_authority_status(
            &SessionStore::with_record(session_record(now)),
            &AuthorityStore::with_record(authority),
            &FixedClock(now),
            GetCreatorAuthorityStatusRequest {
                session_token: FrontendSessionToken::new("frontend-session-token"),
            },
        )
        .await
        .unwrap();

        assert_eq!(status.creator, creator());
        assert!(status.authorized);
        assert_eq!(
            status.auth_kind,
            Some(CreatorAuthorityAuthKind::LegacyCookie)
        );
        assert_eq!(
            status.granted_scopes,
            vec!["/pub/locks.app/:rw", "/priv/locks.app/:rw"]
        );
        assert_eq!(status.session_expires_at, Some(session_expires_at));

        let debug = format!("{status:?}");
        assert!(!debug.contains("creator-authority-secret"));
        assert!(!debug.contains("frontend-session-token"));
    }

    #[tokio::test]
    async fn public_status_is_authorized_only_when_the_homeserver_still_honors_the_cookie() {
        let usable = get_public_creator_authority_status(
            &manager(
                AuthorityStore::with_record(cookie_record()),
                HomeserverAnswer::Honored,
                HomeserverAnswer::Honored,
            ),
            creator(),
        )
        .await
        .unwrap();
        assert_eq!(usable.creator, creator());
        assert!(usable.authorized);
        assert!(!format!("{usable:?}").contains("creator-authority-secret"));

        let missing = get_public_creator_authority_status(
            &manager(
                AuthorityStore::default(),
                HomeserverAnswer::Honored,
                HomeserverAnswer::Honored,
            ),
            creator(),
        )
        .await
        .unwrap();
        assert!(!missing.authorized);
    }

    #[tokio::test]
    async fn public_status_reports_a_revoked_cookie_row_as_not_authorized() {
        let status = get_public_creator_authority_status(
            &manager(
                AuthorityStore::with_record(cookie_record()),
                HomeserverAnswer::Refused,
                HomeserverAnswer::Honored,
            ),
            creator(),
        )
        .await
        .unwrap();

        assert!(!status.authorized);
    }

    #[tokio::test]
    async fn public_status_reports_an_expired_grant_row_as_not_authorized() {
        let expired_grant = CreatorAuthorityRecord {
            auth_kind: CreatorAuthorityAuthKind::Grant,
            session_expires_at: Some(OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()),
            ..cookie_record()
        };

        let status = get_public_creator_authority_status(
            &manager(
                AuthorityStore::with_record(expired_grant),
                HomeserverAnswer::Honored,
                HomeserverAnswer::Refused,
            ),
            creator(),
        )
        .await
        .unwrap();

        assert!(!status.authorized);
    }

    #[tokio::test]
    async fn public_status_surfaces_storage_failures_instead_of_reporting_not_authorized() {
        let error = get_public_creator_authority_status(
            &LegacyCookieCreatorAuthorityManager::new(
                FailingAuthorityStore,
                CookieHomeserver(HomeserverAnswer::Honored),
            ),
            creator(),
        )
        .await
        .unwrap_err();

        assert!(matches!(error, ApplicationError::Storage { .. }));
    }

    #[derive(Debug, Clone, Copy)]
    enum HomeserverAnswer {
        Honored,
        Refused,
    }

    impl HomeserverAnswer {
        fn result(self, message: &str) -> Result<(), ApplicationError> {
            match self {
                Self::Honored => Ok(()),
                Self::Refused => Err(ApplicationError::CreatorAuthoritySecret {
                    message: message.to_owned(),
                }),
            }
        }
    }

    /// Stands in for the homeserver's answer to a cookie-session restore.
    struct CookieHomeserver(HomeserverAnswer);

    #[async_trait]
    impl LegacyCookieSessionRevalidator for CookieHomeserver {
        async fn revalidate_legacy_cookie_secret(
            &self,
            _secret: &CreatorAuthoritySecret,
        ) -> Result<(), ApplicationError> {
            self.0
                .result("failed to restore legacy creator authority secret")
        }
    }

    /// Stands in for the homeserver's answer to a delegated grant restore.
    struct GrantHomeserver(HomeserverAnswer);

    #[async_trait]
    impl GrantCredentialRevalidator for GrantHomeserver {
        async fn revalidate_grant_credential(
            &self,
            _creator: &CreatorPubky,
            _secret: &CreatorAuthoritySecret,
        ) -> Result<(), ApplicationError> {
            self.0.result("failed to restore grant creator authority")
        }
    }

    fn manager(
        store: AuthorityStore,
        cookie: HomeserverAnswer,
        grant: HomeserverAnswer,
    ) -> impl CreatorAuthorityManager {
        LegacyCookieCreatorAuthorityManager::new(store, CookieHomeserver(cookie))
            .with_grant_revalidator(GrantHomeserver(grant))
    }

    fn cookie_record() -> CreatorAuthorityRecord {
        CreatorAuthorityRecord {
            creator: creator(),
            auth_kind: CreatorAuthorityAuthKind::LegacyCookie,
            granted_scopes: vec!["/pub/locks.app/:rw".to_owned()],
            secret: CreatorAuthoritySecret::new("creator-authority-secret"),
            session_expires_at: None,
            last_revalidated_at: None,
        }
    }

    struct FailingAuthorityStore;

    #[async_trait]
    impl CreatorAuthorityStore for FailingAuthorityStore {
        async fn upsert_creator_authority(
            &self,
            _authority: CreatorAuthorityRecord,
        ) -> Result<(), ApplicationError> {
            Err(storage_failure())
        }

        async fn get_creator_authority(
            &self,
            _creator: &CreatorPubky,
        ) -> Result<Option<CreatorAuthorityRecord>, ApplicationError> {
            Err(storage_failure())
        }

        async fn delete_creator_authority(
            &self,
            _creator: &CreatorPubky,
        ) -> Result<(), ApplicationError> {
            Err(storage_failure())
        }
    }

    fn storage_failure() -> ApplicationError {
        ApplicationError::Storage {
            message: "connection refused".to_owned(),
        }
    }

    fn session_record(now: OffsetDateTime) -> FrontendSessionRecord {
        FrontendSessionRecord {
            token: FrontendSessionToken::new("frontend-session-token"),
            creator: creator(),
            created_at: now,
            expires_at: now + Duration::hours(12),
        }
    }

    fn creator() -> CreatorPubky {
        CreatorPubky::from_str("pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy").unwrap()
    }

    #[derive(Debug, Default)]
    struct SessionStore {
        record: Mutex<Option<FrontendSessionRecord>>,
    }

    impl SessionStore {
        fn with_record(record: FrontendSessionRecord) -> Self {
            Self {
                record: Mutex::new(Some(record)),
            }
        }
    }

    #[async_trait]
    impl FrontendSessionStore for SessionStore {
        async fn insert_frontend_session(
            &self,
            record: FrontendSessionRecord,
        ) -> Result<(), ApplicationError> {
            *self.record.lock().unwrap() = Some(record);
            Ok(())
        }

        async fn get_frontend_session(
            &self,
            _token: &FrontendSessionToken,
        ) -> Result<Option<FrontendSessionRecord>, ApplicationError> {
            Ok(self.record.lock().unwrap().clone())
        }

        async fn delete_frontend_session(
            &self,
            _token: &FrontendSessionToken,
        ) -> Result<(), ApplicationError> {
            *self.record.lock().unwrap() = None;
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct AuthorityStore {
        record: Mutex<Option<CreatorAuthorityRecord>>,
    }

    impl AuthorityStore {
        fn with_record(record: CreatorAuthorityRecord) -> Self {
            Self {
                record: Mutex::new(Some(record)),
            }
        }
    }

    #[async_trait]
    impl CreatorAuthorityStore for AuthorityStore {
        async fn upsert_creator_authority(
            &self,
            authority: CreatorAuthorityRecord,
        ) -> Result<(), ApplicationError> {
            *self.record.lock().unwrap() = Some(authority);
            Ok(())
        }

        async fn get_creator_authority(
            &self,
            _creator: &CreatorPubky,
        ) -> Result<Option<CreatorAuthorityRecord>, ApplicationError> {
            Ok(self.record.lock().unwrap().clone())
        }

        async fn delete_creator_authority(
            &self,
            _creator: &CreatorPubky,
        ) -> Result<(), ApplicationError> {
            *self.record.lock().unwrap() = None;
            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }
}
