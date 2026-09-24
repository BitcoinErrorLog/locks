use std::future::Future;

use locks_core::ids::CreatorPubky;
use time::{Duration, OffsetDateTime};

use crate::application::errors::ApplicationError;
use crate::application::models::{
    CreatorAuthorityAuthKind, CreatorAuthorityRecord, CreatorAuthoritySecret, CreatorConnectFlowId,
    FrontendSessionCode, FrontendSessionCodeRecord, GrantPopKeyId, PendingCreatorConnectFlowRecord,
};
use crate::application::ports::{
    Clock, CreatorAuthorityStore, CreatorConnectFlowStore, FrontendSessionCodeGenerator,
    FrontendSessionCodeStore, GrantCreatorConnectFlowClient, LegacyCreatorConnectFlowClient,
};

const FRONTEND_SESSION_CODE_TTL: Duration = Duration::minutes(5);

/// Request to complete a pending creator connect flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteCreatorConnectFlowRequest {
    /// Pending flow ID returned from start flow.
    pub flow_id: CreatorConnectFlowId,
}

/// Response containing a one-time frontend session code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteCreatorConnectFlowResponse {
    /// Creator approved by Pubky signer.
    pub creator: locks_core::ids::CreatorPubky,
    /// Opaque state from the original pending flow.
    pub state: String,
    /// Return target from the original pending flow.
    pub return_to: String,
    /// One-time code to exchange for a frontend session.
    pub code: FrontendSessionCode,
    /// Expiration timestamp for the one-time code.
    pub code_expires_at: OffsetDateTime,
}

/// Completes a pending Pubky creator connect flow and issues a frontend session code.
///
/// A flow started with a grant URL waits for both approvals and completes with the first
/// one that succeeds. A cookie approval stores a `LegacyCookie` record; a grant approval
/// stores a `Grant` record holding delegated restore state.
#[allow(clippy::too_many_arguments)]
pub async fn complete_creator_connect_flow(
    flow_store: &dyn CreatorConnectFlowStore,
    authority_store: &dyn CreatorAuthorityStore,
    code_store: &dyn FrontendSessionCodeStore,
    client: &dyn LegacyCreatorConnectFlowClient,
    grant_client: Option<&dyn GrantCreatorConnectFlowClient>,
    code_generator: &dyn FrontendSessionCodeGenerator,
    clock: &dyn Clock,
    request: CompleteCreatorConnectFlowRequest,
) -> Result<CompleteCreatorConnectFlowResponse, ApplicationError> {
    let now = clock.now();
    let pending = flow_store
        .get_pending_creator_connect_flow(&request.flow_id)
        .await?
        .ok_or(ApplicationError::CreatorConnectFlowUnavailable)?;

    if pending.is_expired_at(now) {
        flow_store
            .delete_pending_creator_connect_flow(&request.flow_id)
            .await?;
        return Err(ApplicationError::CreatorConnectFlowExpired);
    }

    let approval = await_connect_approval(client, grant_client, &pending).await?;
    let authority = CreatorAuthorityRecord {
        creator: approval.creator.clone(),
        auth_kind: approval.auth_kind,
        granted_scopes: approval.granted_scopes,
        secret: approval.secret,
        session_expires_at: approval.session_expires_at,
        last_revalidated_at: Some(now),
    };
    authority_store.upsert_creator_authority(authority).await?;

    let code = code_generator.generate_frontend_session_code();
    let code_expires_at = now + FRONTEND_SESSION_CODE_TTL;
    code_store
        .insert_frontend_session_code(FrontendSessionCodeRecord {
            code: code.clone(),
            creator: approval.creator.clone(),
            state: pending.state.clone(),
            return_to: pending.return_to.clone(),
            created_at: now,
            expires_at: code_expires_at,
            consumed_at: None,
        })
        .await?;

    flow_store
        .delete_pending_creator_connect_flow(&request.flow_id)
        .await?;

    Ok(CompleteCreatorConnectFlowResponse {
        creator: approval.creator,
        state: pending.state,
        return_to: pending.return_to,
        code,
        code_expires_at,
    })
}

struct ConnectApproval {
    creator: CreatorPubky,
    auth_kind: CreatorAuthorityAuthKind,
    granted_scopes: Vec<String>,
    secret: CreatorAuthoritySecret,
    session_expires_at: Option<OffsetDateTime>,
}

async fn await_connect_approval(
    client: &dyn LegacyCreatorConnectFlowClient,
    grant_client: Option<&dyn GrantCreatorConnectFlowClient>,
    pending: &PendingCreatorConnectFlowRecord,
) -> Result<ConnectApproval, ApplicationError> {
    let cookie = async {
        client
            .await_legacy_creator_connect_flow_approval(&pending.authorization_url)
            .await
            .map(|approval| ConnectApproval {
                creator: approval.creator,
                auth_kind: CreatorAuthorityAuthKind::LegacyCookie,
                granted_scopes: pending.requested_scopes.clone(),
                secret: approval.session_secret,
                session_expires_at: None,
            })
    };
    let (Some(grant_client), Some(grant_authorization_url)) =
        (grant_client, pending.grant_authorization_url.as_ref())
    else {
        return cookie.await;
    };
    let pop_key_id = GrantPopKeyId::for_connect_flow(&pending.flow_id);
    let grant = async {
        grant_client
            .await_grant_creator_connect_flow_approval(
                grant_authorization_url,
                &pop_key_id,
                &pending.requested_scopes,
            )
            .await
            .map(|approval| ConnectApproval {
                creator: approval.creator,
                auth_kind: CreatorAuthorityAuthKind::Grant,
                granted_scopes: approval.granted_scopes,
                secret: approval.grant_state,
                session_expires_at: Some(approval.grant_expires_at),
            })
    };
    first_approval(cookie, grant).await
}

/// Resolves with the first successful approval. When both fail, the cookie error wins so
/// existing callers keep seeing the legacy failure.
async fn first_approval<C, G>(cookie: C, grant: G) -> Result<ConnectApproval, ApplicationError>
where
    C: Future<Output = Result<ConnectApproval, ApplicationError>>,
    G: Future<Output = Result<ConnectApproval, ApplicationError>>,
{
    tokio::pin!(cookie);
    tokio::pin!(grant);
    tokio::select! {
        result = &mut cookie => match result {
            Ok(approval) => Ok(approval),
            Err(cookie_error) => grant.await.map_err(|_| cookie_error),
        },
        result = &mut grant => match result {
            Ok(approval) => Ok(approval),
            Err(_) => cookie.await,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use locks_core::ids::CreatorPubky;
    use time::{Duration, OffsetDateTime};

    use crate::application::errors::ApplicationError;
    use crate::application::models::{
        CreatorAuthorityAuthKind, CreatorAuthorityCheckOutcome, CreatorAuthorityRecord,
        CreatorAuthoritySecret, CreatorAuthorityValidity, CreatorConnectAuthorizationUrl,
        CreatorConnectFlowId, FrontendSessionCode, FrontendSessionCodeRecord,
        GrantCreatorConnectFlowApproval, GrantPopKeyId, LegacyCreatorConnectFlowApproval,
        PendingCreatorConnectFlowRecord,
    };
    use crate::application::ports::{
        Clock, CreatorAuthorityStore, CreatorConnectFlowStore, FrontendSessionCodeGenerator,
        FrontendSessionCodeStore, GrantCreatorConnectFlowClient, LegacyCreatorConnectFlowClient,
    };
    use crate::application::use_cases::complete_creator_connect_flow::{
        CompleteCreatorConnectFlowRequest, complete_creator_connect_flow,
    };

    const GRANT_STATE: &str = "{\"delegated-grant-restore-state\":true}";

    fn grant_pending_flow(now: OffsetDateTime) -> PendingCreatorConnectFlowRecord {
        PendingCreatorConnectFlowRecord {
            grant_authorization_url: Some(CreatorConnectAuthorizationUrl::new(
                "pubkyauth://signin_grant?secret-grant-url",
            )),
            ..pending_flow(now)
        }
    }

    async fn complete_with(
        flow_store: &FlowStore,
        authority_store: &AuthorityStore,
        cookie: Outcome,
        grant: Option<&ScriptedGrantClient>,
        now: OffsetDateTime,
    ) -> Result<super::CompleteCreatorConnectFlowResponse, ApplicationError> {
        complete_creator_connect_flow(
            flow_store,
            authority_store,
            &CodeStore::default(),
            &ScriptedCookieClient(cookie),
            grant.map(|client| client as &dyn GrantCreatorConnectFlowClient),
            &FixedCodeGenerator,
            &FixedClock(now),
            CompleteCreatorConnectFlowRequest {
                flow_id: CreatorConnectFlowId::new("flow-123"),
            },
        )
        .await
    }

    #[tokio::test]
    async fn grant_connect_stores_grant_record_while_cookie_flow_is_pending() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let flow_store = FlowStore::with_record(grant_pending_flow(now));
        let authority_store = AuthorityStore::default();
        let grant_client = ScriptedGrantClient::new(Outcome::Approve);

        let response = complete_with(
            &flow_store,
            &authority_store,
            Outcome::Pending,
            Some(&grant_client),
            now,
        )
        .await
        .unwrap();

        assert_eq!(response.creator, creator());
        assert_eq!(response.code.expose_code(), "one-time-code");
        let authority = authority_store.record().expect("grant authority stored");
        assert_eq!(authority.auth_kind, CreatorAuthorityAuthKind::Grant);
        assert_eq!(authority.secret.expose_secret(), GRANT_STATE);
        assert_eq!(
            authority.granted_scopes,
            vec!["/priv/locks.app/:rw", "/pub/locks.app/:rw"]
        );
        assert_eq!(authority.session_expires_at, Some(now + Duration::days(30)));
        assert!(flow_store.record().is_none(), "pending flow deleted");
        assert_eq!(
            grant_client.awaited(),
            vec![(
                "pubkyauth://signin_grant?secret-grant-url".to_owned(),
                GrantPopKeyId::for_connect_flow(&CreatorConnectFlowId::new("flow-123")),
                vec![
                    "/pub/locks.app/:rw".to_owned(),
                    "/priv/locks.app/:rw".to_owned()
                ],
            )]
        );
    }

    #[tokio::test]
    async fn grant_record_never_passes_through_cookie_slot() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let authority_store = AuthorityStore::default();
        complete_with(
            &FlowStore::with_record(grant_pending_flow(now)),
            &authority_store,
            Outcome::Fail,
            Some(&ScriptedGrantClient::new(Outcome::Approve)),
            now,
        )
        .await
        .unwrap();
        let grant_record = authority_store.record().unwrap();
        assert_eq!(grant_record.auth_kind, CreatorAuthorityAuthKind::Grant);
        assert_ne!(
            grant_record.secret.expose_secret(),
            "legacy-cookie-session-secret"
        );

        let cookie_store = AuthorityStore::default();
        complete_with(
            &FlowStore::with_record(grant_pending_flow(now)),
            &cookie_store,
            Outcome::Approve,
            Some(&ScriptedGrantClient::new(Outcome::Pending)),
            now,
        )
        .await
        .unwrap();
        let cookie_record = cookie_store.record().unwrap();
        assert_eq!(
            cookie_record.auth_kind,
            CreatorAuthorityAuthKind::LegacyCookie
        );
        assert_eq!(
            cookie_record.secret.expose_secret(),
            "legacy-cookie-session-secret"
        );
        assert_eq!(cookie_record.session_expires_at, None);
    }

    #[tokio::test]
    async fn failed_grant_approval_still_completes_with_cookie_approval() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let authority_store = AuthorityStore::default();

        complete_with(
            &FlowStore::with_record(grant_pending_flow(now)),
            &authority_store,
            Outcome::Approve,
            Some(&ScriptedGrantClient::new(Outcome::Fail)),
            now,
        )
        .await
        .unwrap();

        assert_eq!(
            authority_store.record().unwrap().auth_kind,
            CreatorAuthorityAuthKind::LegacyCookie
        );
    }

    #[tokio::test]
    async fn both_failed_approvals_return_the_cookie_error_and_store_nothing() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let flow_store = FlowStore::with_record(grant_pending_flow(now));
        let authority_store = AuthorityStore::default();

        let error = complete_with(
            &flow_store,
            &authority_store,
            Outcome::Fail,
            Some(&ScriptedGrantClient::new(Outcome::Fail)),
            now,
        )
        .await
        .unwrap_err();

        assert_eq!(error, cookie_error());
        assert!(authority_store.record().is_none());
        assert!(flow_store.record().is_some(), "pending flow kept for retry");
    }

    #[tokio::test]
    async fn flow_without_grant_url_never_awaits_grant_approval() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let authority_store = AuthorityStore::default();
        let grant_client = ScriptedGrantClient::new(Outcome::Approve);

        complete_with(
            &FlowStore::with_record(pending_flow(now)),
            &authority_store,
            Outcome::Approve,
            Some(&grant_client),
            now,
        )
        .await
        .unwrap();

        assert!(grant_client.awaited().is_empty());
        assert_eq!(
            authority_store.record().unwrap().auth_kind,
            CreatorAuthorityAuthKind::LegacyCookie
        );
    }

    #[derive(Clone, Copy)]
    enum Outcome {
        Approve,
        Fail,
        Pending,
    }

    fn cookie_error() -> ApplicationError {
        ApplicationError::CreatorAuthoritySecret {
            message: "legacy creator connect flow approval failed or expired".to_owned(),
        }
    }

    struct ScriptedCookieClient(Outcome);

    #[async_trait]
    impl LegacyCreatorConnectFlowClient for ScriptedCookieClient {
        async fn start_legacy_creator_connect_flow(
            &self,
            _requested_scopes: &[String],
        ) -> Result<CreatorConnectAuthorizationUrl, ApplicationError> {
            unreachable!("complete use case must not start new flow")
        }

        async fn await_legacy_creator_connect_flow_approval(
            &self,
            _authorization_url: &CreatorConnectAuthorizationUrl,
        ) -> Result<LegacyCreatorConnectFlowApproval, ApplicationError> {
            match self.0 {
                Outcome::Approve => Ok(LegacyCreatorConnectFlowApproval {
                    creator: creator(),
                    session_secret: CreatorAuthoritySecret::new("legacy-cookie-session-secret"),
                }),
                Outcome::Fail => Err(cookie_error()),
                Outcome::Pending => std::future::pending().await,
            }
        }
    }

    struct ScriptedGrantClient {
        outcome: Outcome,
        awaited: Mutex<Vec<(String, GrantPopKeyId, Vec<String>)>>,
    }

    impl ScriptedGrantClient {
        fn new(outcome: Outcome) -> Self {
            Self {
                outcome,
                awaited: Mutex::new(Vec::new()),
            }
        }

        fn awaited(&self) -> Vec<(String, GrantPopKeyId, Vec<String>)> {
            self.awaited.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl GrantCreatorConnectFlowClient for ScriptedGrantClient {
        async fn start_grant_creator_connect_flow(
            &self,
            _requested_scopes: &[String],
            _pop_key_id: &GrantPopKeyId,
        ) -> Result<CreatorConnectAuthorizationUrl, ApplicationError> {
            unreachable!("complete use case must not start new flow")
        }

        async fn await_grant_creator_connect_flow_approval(
            &self,
            authorization_url: &CreatorConnectAuthorizationUrl,
            pop_key_id: &GrantPopKeyId,
            requested_scopes: &[String],
        ) -> Result<GrantCreatorConnectFlowApproval, ApplicationError> {
            self.awaited.lock().unwrap().push((
                authorization_url.expose_url().to_owned(),
                pop_key_id.clone(),
                requested_scopes.to_vec(),
            ));
            match self.outcome {
                Outcome::Approve => Ok(GrantCreatorConnectFlowApproval {
                    creator: creator(),
                    grant_state: CreatorAuthoritySecret::new(GRANT_STATE),
                    granted_scopes: vec![
                        "/priv/locks.app/:rw".to_owned(),
                        "/pub/locks.app/:rw".to_owned(),
                    ],
                    grant_expires_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
                        + Duration::days(30),
                }),
                Outcome::Fail => Err(ApplicationError::CreatorAuthoritySecret {
                    message: "grant creator connect flow approval failed or expired".to_owned(),
                }),
                Outcome::Pending => std::future::pending().await,
            }
        }
    }

    #[tokio::test]
    async fn complete_creator_connect_flow_stores_authority_issues_code_and_deletes_pending_flow() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let flow_store = FlowStore::with_record(pending_flow(now));
        let authority_store = AuthorityStore::default();
        let code_store = CodeStore::default();
        let client = FakeConnectFlowClient;
        let code_generator = FixedCodeGenerator;
        let clock = FixedClock(now);

        let response = complete_creator_connect_flow(
            &flow_store,
            &authority_store,
            &code_store,
            &client,
            None,
            &code_generator,
            &clock,
            CompleteCreatorConnectFlowRequest {
                flow_id: CreatorConnectFlowId::new("flow-123"),
            },
        )
        .await
        .unwrap();

        assert_eq!(response.creator, creator());
        assert_eq!(response.state, "opaque-state");
        assert_eq!(response.return_to, "https://pubky.app/locks/connected");
        assert_eq!(response.code.expose_code(), "one-time-code");
        assert!(response.code_expires_at <= now + Duration::minutes(5));
        assert!(!format!("{response:?}").contains("legacy-cookie-session-secret"));

        assert!(
            flow_store.record().is_none(),
            "pending flow deleted after completion"
        );

        let authority = authority_store.record().expect("creator authority stored");
        assert_eq!(authority.creator, creator());
        assert_eq!(authority.auth_kind, CreatorAuthorityAuthKind::LegacyCookie);
        assert_eq!(
            authority.secret.expose_secret(),
            "legacy-cookie-session-secret"
        );
        assert_eq!(
            authority.granted_scopes,
            vec!["/pub/locks.app/:rw", "/priv/locks.app/:rw"]
        );

        let code = code_store.record().expect("frontend session code stored");
        assert_eq!(code.code.expose_code(), "one-time-code");
        assert_eq!(code.creator, creator());
        assert_eq!(code.state, "opaque-state");
        assert_eq!(code.return_to, "https://pubky.app/locks/connected");
        assert_eq!(code.created_at, now);
        assert_eq!(code.expires_at, response.code_expires_at);
        assert_eq!(code.consumed_at, None);
    }

    #[tokio::test]
    async fn complete_creator_connect_flow_maps_missing_and_expired_flows_to_lifecycle_errors() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let missing = complete_creator_connect_flow(
            &FlowStore::default(),
            &AuthorityStore::default(),
            &CodeStore::default(),
            &FakeConnectFlowClient,
            None,
            &FixedCodeGenerator,
            &FixedClock(now),
            CompleteCreatorConnectFlowRequest {
                flow_id: CreatorConnectFlowId::new("missing"),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(missing, ApplicationError::CreatorConnectFlowUnavailable);

        let expired_flow = PendingCreatorConnectFlowRecord {
            expires_at: now,
            ..pending_flow(now - Duration::minutes(10))
        };
        let expired_store = FlowStore::with_record(expired_flow);
        let expired = complete_creator_connect_flow(
            &expired_store,
            &AuthorityStore::default(),
            &CodeStore::default(),
            &FakeConnectFlowClient,
            None,
            &FixedCodeGenerator,
            &FixedClock(now),
            CompleteCreatorConnectFlowRequest {
                flow_id: CreatorConnectFlowId::new("flow-123"),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(expired, ApplicationError::CreatorConnectFlowExpired);
        assert!(expired_store.record().is_none(), "expired flow cleaned up");
    }

    fn pending_flow(now: OffsetDateTime) -> PendingCreatorConnectFlowRecord {
        PendingCreatorConnectFlowRecord {
            flow_id: CreatorConnectFlowId::new("flow-123"),
            return_to: "https://pubky.app/locks/connected".to_owned(),
            state: "opaque-state".to_owned(),
            authorization_url: CreatorConnectAuthorizationUrl::new("pubkyauth://secret-flow-url"),
            grant_authorization_url: None,
            requested_scopes: vec![
                "/pub/locks.app/:rw".to_owned(),
                "/priv/locks.app/:rw".to_owned(),
            ],
            created_at: now,
            expires_at: now + Duration::minutes(5),
        }
    }

    fn creator() -> CreatorPubky {
        CreatorPubky::from_str("pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy").unwrap()
    }

    #[derive(Default)]
    struct FlowStore {
        record: Mutex<Option<PendingCreatorConnectFlowRecord>>,
    }

    impl FlowStore {
        fn with_record(record: PendingCreatorConnectFlowRecord) -> Self {
            Self {
                record: Mutex::new(Some(record)),
            }
        }

        fn record(&self) -> Option<PendingCreatorConnectFlowRecord> {
            self.record.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl CreatorConnectFlowStore for FlowStore {
        async fn insert_pending_creator_connect_flow(
            &self,
            record: PendingCreatorConnectFlowRecord,
        ) -> Result<(), ApplicationError> {
            *self.record.lock().unwrap() = Some(record);
            Ok(())
        }

        async fn get_pending_creator_connect_flow(
            &self,
            _flow_id: &CreatorConnectFlowId,
        ) -> Result<Option<PendingCreatorConnectFlowRecord>, ApplicationError> {
            Ok(self.record())
        }

        async fn delete_pending_creator_connect_flow(
            &self,
            _flow_id: &CreatorConnectFlowId,
        ) -> Result<(), ApplicationError> {
            *self.record.lock().unwrap() = None;
            Ok(())
        }
    }

    #[derive(Default)]
    struct AuthorityStore {
        record: Mutex<Option<CreatorAuthorityRecord>>,
    }

    impl AuthorityStore {
        fn record(&self) -> Option<CreatorAuthorityRecord> {
            self.record.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl CreatorAuthorityStore for AuthorityStore {
        async fn get_creator_authority(
            &self,
            _creator: &CreatorPubky,
        ) -> Result<Option<CreatorAuthorityRecord>, ApplicationError> {
            Ok(self.record())
        }

        async fn upsert_creator_authority(
            &self,
            record: CreatorAuthorityRecord,
        ) -> Result<(), ApplicationError> {
            *self.record.lock().unwrap() = Some(record);
            Ok(())
        }

        async fn get_creator_authority_validity(
            &self,
            _creator: &CreatorPubky,
        ) -> Result<Option<CreatorAuthorityValidity>, ApplicationError> {
            Ok(self
                .record()
                .map(|record| CreatorAuthorityValidity::from_record(&record, None)))
        }

        async fn record_creator_authority_check(
            &self,
            _creator: &CreatorPubky,
            _outcome: CreatorAuthorityCheckOutcome,
            _checked_at: OffsetDateTime,
        ) -> Result<(), ApplicationError> {
            unimplemented!("connect-flow completion never revalidates")
        }

        async fn delete_creator_authority(
            &self,
            _creator: &CreatorPubky,
        ) -> Result<(), ApplicationError> {
            *self.record.lock().unwrap() = None;
            Ok(())
        }
    }

    #[derive(Default)]
    struct CodeStore {
        record: Mutex<Option<FrontendSessionCodeRecord>>,
    }

    impl CodeStore {
        fn record(&self) -> Option<FrontendSessionCodeRecord> {
            self.record.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl FrontendSessionCodeStore for CodeStore {
        async fn insert_frontend_session_code(
            &self,
            record: FrontendSessionCodeRecord,
        ) -> Result<(), ApplicationError> {
            *self.record.lock().unwrap() = Some(record);
            Ok(())
        }

        async fn consume_frontend_session_code(
            &self,
            _code: &FrontendSessionCode,
            _now: OffsetDateTime,
        ) -> Result<Option<FrontendSessionCodeRecord>, ApplicationError> {
            Ok(self.record())
        }
    }

    struct FakeConnectFlowClient;

    #[async_trait]
    impl LegacyCreatorConnectFlowClient for FakeConnectFlowClient {
        async fn start_legacy_creator_connect_flow(
            &self,
            _requested_scopes: &[String],
        ) -> Result<CreatorConnectAuthorizationUrl, ApplicationError> {
            unreachable!("complete use case must not start new flow")
        }

        async fn await_legacy_creator_connect_flow_approval(
            &self,
            _authorization_url: &CreatorConnectAuthorizationUrl,
        ) -> Result<LegacyCreatorConnectFlowApproval, ApplicationError> {
            Ok(LegacyCreatorConnectFlowApproval {
                creator: creator(),
                session_secret: CreatorAuthoritySecret::new("legacy-cookie-session-secret"),
            })
        }
    }

    struct FixedCodeGenerator;

    impl FrontendSessionCodeGenerator for FixedCodeGenerator {
        fn generate_frontend_session_code(&self) -> FrontendSessionCode {
            FrontendSessionCode::new("one-time-code")
        }
    }

    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }
}
