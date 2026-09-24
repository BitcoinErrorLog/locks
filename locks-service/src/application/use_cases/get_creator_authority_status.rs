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
///
/// The caller holds the creator's own frontend-session bearer, so this route runs a real
/// revalidation first; the manager records the homeserver's answer. It then answers with
/// the same stored-validity rule as [`get_public_creator_authority_status`], so the two
/// routes cannot disagree. An unreachable homeserver leaves the stored answer in place; a
/// local secret failure (for example a wrong encryption key) is an error, never `false`.
pub async fn get_creator_authority_status(
    frontend_sessions: &dyn FrontendSessionStore,
    creator_authorities: &dyn CreatorAuthorityStore,
    creator_authority_manager: &dyn CreatorAuthorityManager,
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
    match creator_authority_manager
        .revalidate_creator_authority(&creator)
        .await
    {
        Ok(_)
        | Err(
            ApplicationError::CreatorAuthorityUnavailable
            | ApplicationError::CreatorAuthorityRefused
            | ApplicationError::CreatorAuthorityCheckUnavailable,
        ) => {}
        Err(error) => return Err(error),
    }

    let validity = creator_authorities
        .get_creator_authority_validity(&creator)
        .await?
        .filter(|validity| validity.is_usable_at(now));
    Ok(match validity {
        Some(validity) => CreatorAuthorityStatusView {
            creator,
            authorized: true,
            auth_kind: Some(validity.auth_kind),
            granted_scopes: validity.granted_scopes,
            session_expires_at: validity.session_expires_at,
        },
        None => CreatorAuthorityStatusView {
            creator,
            authorized: false,
            auth_kind: None,
            granted_scopes: Vec::new(),
            session_expires_at: None,
        },
    })
}

/// Creator-keyed status that carries no session, auth kind, scopes, or expiry.
///
/// Callers learn only whether this Lock Server holds usable creator authority for
/// `creator`, so a seller UI can show the connection after its frontend session has
/// expired or its browser storage was cleared, without asking the creator to approve again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicCreatorAuthorityStatusView {
    /// Creator identity from the request path, in canonical form.
    pub creator: CreatorPubky,
    /// [`crate::application::models::CreatorAuthorityValidity::is_usable_at`] for the stored
    /// authority.
    pub authorized: bool,
}

/// Returns whether this Lock Server holds usable creator authority, without a frontend session.
///
/// Anonymous callers get an answer from locally stored validity only: one primary-key read
/// of non-secret columns, the same for present and absent rows. It never loads or decrypts
/// the secret and never contacts a homeserver. The stored validity is refreshed by every
/// real revalidation — content, entitlement, and payment-path homeserver I/O, and the
/// authenticated status route — which records the homeserver's refusal or acceptance.
pub async fn get_public_creator_authority_status(
    creator_authorities: &dyn CreatorAuthorityStore,
    clock: &dyn Clock,
    creator: CreatorPubky,
) -> Result<PublicCreatorAuthorityStatusView, ApplicationError> {
    let now = clock.now();
    let authorized = creator_authorities
        .get_creator_authority_validity(&creator)
        .await?
        .is_some_and(|validity| validity.is_usable_at(now));
    Ok(PublicCreatorAuthorityStatusView {
        creator,
        authorized,
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use locks_core::ids::CreatorPubky;
    use time::{Duration, OffsetDateTime};

    use super::{
        GetCreatorAuthorityStatusRequest, get_creator_authority_status,
        get_public_creator_authority_status,
    };
    use crate::application::errors::ApplicationError;
    use crate::application::models::{
        CreatorAuthorityAuthKind, CreatorAuthorityCheckOutcome, CreatorAuthorityRecord,
        CreatorAuthoritySecret, CreatorAuthorityValidity, FrontendSessionRecord,
        FrontendSessionToken,
    };
    use crate::application::ports::{
        Clock, CreatorAuthorityManager, CreatorAuthorityStore, FrontendSessionStore,
    };
    use crate::infrastructure::pubky::legacy_creator_authority::{
        GrantCredentialRevalidator, LegacyCookieCreatorAuthorityManager,
        LegacyCookieSessionRevalidator,
    };

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    #[tokio::test]
    async fn authenticated_status_requires_a_live_frontend_session() {
        let store = AuthorityStore::default();
        let homeserver = Homeserver::new(Answer::Honored);

        let missing = get_creator_authority_status(
            &SessionStore::default(),
            &store,
            &homeserver.manager(&store),
            &FixedClock(now()),
            request("missing-token"),
        )
        .await
        .unwrap_err();
        assert_eq!(missing, ApplicationError::FrontendSessionUnavailable);

        let expired = get_creator_authority_status(
            &SessionStore::with_record(FrontendSessionRecord {
                expires_at: now(),
                ..session_record(now() - Duration::hours(12))
            }),
            &store,
            &homeserver.manager(&store),
            &FixedClock(now()),
            request("expired-token"),
        )
        .await
        .unwrap_err();
        assert_eq!(expired, ApplicationError::FrontendSessionExpired);
        assert_eq!(homeserver.calls(), 0);
    }

    #[tokio::test]
    async fn authenticated_status_is_not_authorized_without_a_stored_record() {
        let store = AuthorityStore::default();

        let status = authenticated(&store, &Homeserver::new(Answer::Honored))
            .await
            .unwrap();

        assert_eq!(status.creator, creator());
        assert!(!status.authorized);
        assert_eq!(status.auth_kind, None);
        assert!(status.granted_scopes.is_empty());
        assert_eq!(status.session_expires_at, None);
    }

    #[tokio::test]
    async fn authenticated_status_revalidates_and_records_an_honored_check() {
        let session_expires_at = now() + Duration::days(30);
        let store = AuthorityStore::with_record(CreatorAuthorityRecord {
            session_expires_at: Some(session_expires_at),
            ..cookie_record()
        });
        let homeserver = Homeserver::new(Answer::Honored);

        let status = authenticated(&store, &homeserver).await.unwrap();

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
        assert_eq!(homeserver.calls(), 1);
        assert_eq!(store.checks(), vec![CreatorAuthorityCheckOutcome::Honored]);
        let debug = format!("{status:?}");
        assert!(!debug.contains("creator-authority-secret"));
        assert!(!debug.contains("frontend-session-token"));
    }

    // Stale Connected: before this rule the authenticated route reported row presence.
    #[tokio::test]
    async fn authenticated_status_reports_a_revoked_cookie_and_the_public_route_agrees() {
        let store = AuthorityStore::with_record(cookie_record());

        let status = authenticated(&store, &Homeserver::new(Answer::Refused))
            .await
            .unwrap();

        assert!(!status.authorized);
        assert_eq!(status.auth_kind, None);
        assert_eq!(store.checks(), vec![CreatorAuthorityCheckOutcome::Refused]);
        let public = get_public_creator_authority_status(&store, &FixedClock(now()), creator())
            .await
            .unwrap();
        assert!(!public.authorized);
    }

    #[tokio::test]
    async fn authenticated_status_keeps_the_stored_answer_when_the_homeserver_is_unreachable() {
        let store = AuthorityStore::with_record(cookie_record());

        let status = authenticated(&store, &Homeserver::new(Answer::Unreachable))
            .await
            .unwrap();

        assert!(status.authorized);
        assert!(store.checks().is_empty());
    }

    #[tokio::test]
    async fn authenticated_status_surfaces_a_secret_that_cannot_be_decrypted() {
        let store = AuthorityStore::with_record(cookie_record()).with_undecryptable_secret();
        let homeserver = Homeserver::new(Answer::Honored);

        let error = authenticated(&store, &homeserver).await.unwrap_err();

        assert!(matches!(
            error,
            ApplicationError::CreatorAuthoritySecret { .. }
        ));
        assert_eq!(homeserver.calls(), 0);
        assert!(store.checks().is_empty());
    }

    #[tokio::test]
    async fn authenticated_status_reports_an_expired_grant_even_if_the_homeserver_answers() {
        let store = AuthorityStore::with_record(expired_grant_record());

        let status = authenticated(&store, &Homeserver::new(Answer::Honored))
            .await
            .unwrap();

        assert!(!status.authorized);
    }

    // Amplification: anonymous status must never load the secret or reach a homeserver,
    // and must do the same work for present and absent rows.
    #[tokio::test]
    async fn public_status_reads_only_stored_validity_for_present_and_absent_rows() {
        let present = AuthorityStore::with_record(cookie_record());
        let absent = AuthorityStore::default();

        let connected =
            get_public_creator_authority_status(&present, &FixedClock(now()), creator())
                .await
                .unwrap();
        let unknown = get_public_creator_authority_status(&absent, &FixedClock(now()), creator())
            .await
            .unwrap();

        assert_eq!(connected.creator, creator());
        assert!(connected.authorized);
        assert!(!unknown.authorized);
        for store in [&present, &absent] {
            assert_eq!(store.secret_reads(), 0);
            assert_eq!(store.validity_reads(), 1);
            assert!(store.checks().is_empty());
        }
        assert!(!format!("{connected:?}").contains("creator-authority-secret"));
    }

    #[tokio::test]
    async fn public_status_reports_a_recorded_refusal_and_an_expired_grant_as_not_authorized() {
        let refused = AuthorityStore::with_record(cookie_record());
        refused
            .record_creator_authority_check(
                &creator(),
                CreatorAuthorityCheckOutcome::Refused,
                now(),
            )
            .await
            .unwrap();
        let expired = AuthorityStore::with_record(expired_grant_record());

        for store in [&refused, &expired] {
            let status = get_public_creator_authority_status(store, &FixedClock(now()), creator())
                .await
                .unwrap();
            assert!(!status.authorized);
        }
    }

    #[tokio::test]
    async fn public_status_is_unaffected_by_a_secret_it_never_reads() {
        let store = AuthorityStore::with_record(cookie_record()).with_undecryptable_secret();

        let status = get_public_creator_authority_status(&store, &FixedClock(now()), creator())
            .await
            .unwrap();

        assert!(status.authorized);
        assert_eq!(store.secret_reads(), 0);
    }

    async fn authenticated(
        store: &AuthorityStore,
        homeserver: &Homeserver,
    ) -> Result<super::CreatorAuthorityStatusView, ApplicationError> {
        get_creator_authority_status(
            &SessionStore::with_record(session_record(now())),
            store,
            &homeserver.manager(store),
            &FixedClock(now()),
            request("frontend-session-token"),
        )
        .await
    }

    fn request(token: &str) -> GetCreatorAuthorityStatusRequest {
        GetCreatorAuthorityStatusRequest {
            session_token: FrontendSessionToken::new(token),
        }
    }

    fn cookie_record() -> CreatorAuthorityRecord {
        CreatorAuthorityRecord {
            creator: creator(),
            auth_kind: CreatorAuthorityAuthKind::LegacyCookie,
            granted_scopes: vec![
                "/pub/locks.app/:rw".to_owned(),
                "/priv/locks.app/:rw".to_owned(),
            ],
            secret: CreatorAuthoritySecret::new("creator-authority-secret"),
            session_expires_at: None,
            last_revalidated_at: None,
        }
    }

    fn expired_grant_record() -> CreatorAuthorityRecord {
        CreatorAuthorityRecord {
            auth_kind: CreatorAuthorityAuthKind::Grant,
            session_expires_at: Some(now() - Duration::seconds(1)),
            ..cookie_record()
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

    #[derive(Debug, Clone, Copy)]
    enum Answer {
        Honored,
        Refused,
        Unreachable,
    }

    /// Stands in for the creator's homeserver answering cookie and grant restores.
    #[derive(Clone)]
    struct Homeserver {
        answer: Answer,
        calls: Arc<AtomicUsize>,
    }

    impl Homeserver {
        fn new(answer: Answer) -> Self {
            Self {
                answer,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn answer(&self) -> Result<(), ApplicationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.answer {
                Answer::Honored => Ok(()),
                Answer::Refused => Err(ApplicationError::CreatorAuthorityRefused),
                Answer::Unreachable => Err(ApplicationError::CreatorAuthorityCheckUnavailable),
            }
        }

        fn manager(&self, store: &AuthorityStore) -> impl CreatorAuthorityManager {
            LegacyCookieCreatorAuthorityManager::new(store.clone(), self.clone())
                .with_grant_revalidator(self.clone())
        }
    }

    #[async_trait]
    impl LegacyCookieSessionRevalidator for Homeserver {
        async fn revalidate_legacy_cookie_secret(
            &self,
            _secret: &CreatorAuthoritySecret,
        ) -> Result<(), ApplicationError> {
            self.answer()
        }
    }

    #[async_trait]
    impl GrantCredentialRevalidator for Homeserver {
        async fn revalidate_grant_credential(
            &self,
            _creator: &CreatorPubky,
            _secret: &CreatorAuthoritySecret,
        ) -> Result<(), ApplicationError> {
            self.answer()
        }
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
    struct AuthorityState {
        record: Option<CreatorAuthorityRecord>,
        refused_at: Option<OffsetDateTime>,
        undecryptable: bool,
        secret_reads: usize,
        validity_reads: usize,
        checks: Vec<CreatorAuthorityCheckOutcome>,
    }

    /// One stored creator authority, shared between a manager and the status use cases.
    #[derive(Debug, Clone, Default)]
    struct AuthorityStore(Arc<Mutex<AuthorityState>>);

    impl AuthorityStore {
        fn with_record(record: CreatorAuthorityRecord) -> Self {
            let store = Self::default();
            store.0.lock().unwrap().record = Some(record);
            store
        }

        fn with_undecryptable_secret(self) -> Self {
            self.0.lock().unwrap().undecryptable = true;
            self
        }

        fn secret_reads(&self) -> usize {
            self.0.lock().unwrap().secret_reads
        }

        fn validity_reads(&self) -> usize {
            self.0.lock().unwrap().validity_reads
        }

        fn checks(&self) -> Vec<CreatorAuthorityCheckOutcome> {
            self.0.lock().unwrap().checks.clone()
        }
    }

    #[async_trait]
    impl CreatorAuthorityStore for AuthorityStore {
        async fn upsert_creator_authority(
            &self,
            authority: CreatorAuthorityRecord,
        ) -> Result<(), ApplicationError> {
            let mut state = self.0.lock().unwrap();
            state.record = Some(authority);
            state.refused_at = None;
            Ok(())
        }

        async fn get_creator_authority(
            &self,
            _creator: &CreatorPubky,
        ) -> Result<Option<CreatorAuthorityRecord>, ApplicationError> {
            let mut state = self.0.lock().unwrap();
            state.secret_reads += 1;
            if state.undecryptable && state.record.is_some() {
                return Err(ApplicationError::CreatorAuthoritySecret {
                    message: "failed to decrypt creator authority secret".to_owned(),
                });
            }
            Ok(state.record.clone())
        }

        async fn get_creator_authority_validity(
            &self,
            _creator: &CreatorPubky,
        ) -> Result<Option<CreatorAuthorityValidity>, ApplicationError> {
            let mut state = self.0.lock().unwrap();
            state.validity_reads += 1;
            let refused_at = state.refused_at;
            Ok(state
                .record
                .as_ref()
                .map(|record| CreatorAuthorityValidity::from_record(record, refused_at)))
        }

        async fn record_creator_authority_check(
            &self,
            _creator: &CreatorPubky,
            outcome: CreatorAuthorityCheckOutcome,
            checked_at: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            let mut state = self.0.lock().unwrap();
            state.checks.push(outcome);
            match outcome {
                CreatorAuthorityCheckOutcome::Honored => {
                    state.refused_at = None;
                    if let Some(record) = state.record.as_mut() {
                        record.last_revalidated_at = Some(checked_at);
                    }
                }
                CreatorAuthorityCheckOutcome::Refused => state.refused_at = Some(checked_at),
            }
            Ok(())
        }

        async fn delete_creator_authority(
            &self,
            _creator: &CreatorPubky,
        ) -> Result<(), ApplicationError> {
            let mut state = self.0.lock().unwrap();
            state.record = None;
            state.refused_at = None;
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
