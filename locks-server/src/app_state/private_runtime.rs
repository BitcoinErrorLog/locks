use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use locks_core::ids::CreatorPubky;
use locks_service::application::{
    errors::ApplicationError,
    models::{
        CreatorAuthorityCheckOutcome, CreatorAuthorityRecord, CreatorAuthorityValidity,
        CreatorConnectFlowId, FrontendSessionCode, FrontendSessionCodeRecord,
        FrontendSessionRecord, FrontendSessionToken, PendingCreatorConnectFlowRecord,
    },
    ports::{
        AccessCredentialStore, CreatorAuthorityManager, CreatorAuthorityStore,
        CreatorConnectFlowStore, DueCreatorAuthority, FrontendSessionCodeStore,
        FrontendSessionStore, GrantCreatorConnectFlowClient, LegacyCreatorConnectFlowClient,
        VerificationTaskClaimer, VerificationTaskRepository,
    },
};
use time::OffsetDateTime;
use tokio::sync::RwLock;

#[derive(Clone)]
pub(super) struct PrivateRuntimeAdapters {
    pub(super) verification_tasks: Arc<dyn VerificationTaskRepository>,
    pub(super) verification_task_claimer: Arc<dyn VerificationTaskClaimer>,
    pub(super) access_credentials: Arc<dyn AccessCredentialStore>,
    pub(super) creator_authorities: Arc<dyn CreatorAuthorityStore>,
    pub(super) creator_connect_flows: Arc<dyn CreatorConnectFlowStore>,
    pub(super) frontend_session_codes: Arc<dyn FrontendSessionCodeStore>,
    pub(super) frontend_sessions: Arc<dyn FrontendSessionStore>,
    pub(super) creator_authority_manager: Arc<dyn CreatorAuthorityManager>,
    pub(super) legacy_creator_connect_flow_client: Arc<dyn LegacyCreatorConnectFlowClient>,
    pub(super) grant_creator_connect_flow_client: Option<Arc<dyn GrantCreatorConnectFlowClient>>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct InMemoryCreatorAuthorityStore {
    records: Arc<RwLock<HashMap<CreatorPubky, CreatorAuthorityRecord>>>,
    refusals: Arc<RwLock<HashMap<CreatorPubky, OffsetDateTime>>>,
    schedules: Arc<RwLock<HashMap<CreatorPubky, (OffsetDateTime, u32)>>>,
    lease: Arc<AtomicBool>,
}

impl InMemoryCreatorAuthorityStore {
    pub(super) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CreatorAuthorityStore for InMemoryCreatorAuthorityStore {
    async fn upsert_creator_authority(
        &self,
        authority: CreatorAuthorityRecord,
    ) -> Result<(), ApplicationError> {
        self.refusals.write().await.remove(&authority.creator);
        self.schedules.write().await.remove(&authority.creator);
        self.records
            .write()
            .await
            .insert(authority.creator.clone(), authority);
        Ok(())
    }

    async fn get_creator_authority(
        &self,
        creator: &CreatorPubky,
    ) -> Result<Option<CreatorAuthorityRecord>, ApplicationError> {
        Ok(self.records.read().await.get(creator).cloned())
    }

    async fn get_creator_authority_validity(
        &self,
        creator: &CreatorPubky,
    ) -> Result<Option<CreatorAuthorityValidity>, ApplicationError> {
        let refused_at = self.refusals.read().await.get(creator).copied();
        Ok(self
            .records
            .read()
            .await
            .get(creator)
            .map(|record| CreatorAuthorityValidity::from_record(record, refused_at)))
    }

    async fn record_creator_authority_check(
        &self,
        creator: &CreatorPubky,
        outcome: CreatorAuthorityCheckOutcome,
        checked_at: OffsetDateTime,
    ) -> Result<(), ApplicationError> {
        let mut records = self.records.write().await;
        let Some(record) = records.get_mut(creator) else {
            return Ok(());
        };
        match outcome {
            CreatorAuthorityCheckOutcome::Honored => {
                record.last_revalidated_at = Some(checked_at);
                self.refusals.write().await.remove(creator);
                self.schedules.write().await.remove(creator);
            }
            CreatorAuthorityCheckOutcome::Refused => {
                self.refusals
                    .write()
                    .await
                    .insert(creator.clone(), checked_at);
            }
        }
        Ok(())
    }

    async fn list_creator_authorities_due_for_recheck(
        &self,
        now: OffsetDateTime,
        stale_before: OffsetDateTime,
        limit: u32,
    ) -> Result<Vec<DueCreatorAuthority>, ApplicationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let records = self.records.read().await;
        let refusals = self.refusals.read().await;
        let schedules = self.schedules.read().await;
        let mut due: Vec<(
            Option<OffsetDateTime>,
            Option<OffsetDateTime>,
            DueCreatorAuthority,
        )> = records
            .values()
            .filter_map(|record| {
                let validity = CreatorAuthorityValidity::from_record(
                    record,
                    refusals.get(&record.creator).copied(),
                );
                let scheduled = schedules.get(&record.creator).copied();
                let next_check_at = scheduled.map(|(at, _)| at);
                let failure_count = scheduled.map(|(_, count)| count).unwrap_or(0);
                validity
                    .recheck_due(next_check_at, now, stale_before)
                    .then(|| {
                        (
                            next_check_at,
                            validity.last_checked_at(),
                            DueCreatorAuthority {
                                creator: record.creator.clone(),
                                failure_count,
                            },
                        )
                    })
            })
            .collect();
        due.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.cmp(&right.1))
                .then_with(|| left.2.creator.to_string().cmp(&right.2.creator.to_string()))
        });
        Ok(due
            .into_iter()
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .map(|(_, _, candidate)| candidate)
            .collect())
    }

    async fn schedule_creator_authority_recheck(
        &self,
        creator: &CreatorPubky,
        next_check_at: OffsetDateTime,
        failure_count: u32,
    ) -> Result<(), ApplicationError> {
        self.schedules
            .write()
            .await
            .insert(creator.clone(), (next_check_at, failure_count));
        Ok(())
    }

    async fn try_acquire_revalidation_lease(&self) -> Result<bool, ApplicationError> {
        Ok(self
            .lease
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }

    async fn release_revalidation_lease(&self) -> Result<(), ApplicationError> {
        self.lease.store(false, Ordering::Release);
        Ok(())
    }

    async fn delete_creator_authority(
        &self,
        creator: &CreatorPubky,
    ) -> Result<(), ApplicationError> {
        self.records.write().await.remove(creator);
        self.refusals.write().await.remove(creator);
        self.schedules.write().await.remove(creator);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(super) struct InMemoryCreatorConnectFlowStore {
    records: RwLock<HashMap<CreatorConnectFlowId, PendingCreatorConnectFlowRecord>>,
}

impl InMemoryCreatorConnectFlowStore {
    pub(super) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CreatorConnectFlowStore for InMemoryCreatorConnectFlowStore {
    async fn insert_pending_creator_connect_flow(
        &self,
        record: PendingCreatorConnectFlowRecord,
    ) -> Result<(), ApplicationError> {
        self.records
            .write()
            .await
            .insert(record.flow_id.clone(), record);
        Ok(())
    }

    async fn get_pending_creator_connect_flow(
        &self,
        flow_id: &CreatorConnectFlowId,
    ) -> Result<Option<PendingCreatorConnectFlowRecord>, ApplicationError> {
        Ok(self.records.read().await.get(flow_id).cloned())
    }

    async fn delete_pending_creator_connect_flow(
        &self,
        flow_id: &CreatorConnectFlowId,
    ) -> Result<(), ApplicationError> {
        self.records.write().await.remove(flow_id);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(super) struct InMemoryFrontendSessionCodeStore {
    records: RwLock<HashMap<FrontendSessionCode, FrontendSessionCodeRecord>>,
}

impl InMemoryFrontendSessionCodeStore {
    pub(super) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl FrontendSessionCodeStore for InMemoryFrontendSessionCodeStore {
    async fn insert_frontend_session_code(
        &self,
        record: FrontendSessionCodeRecord,
    ) -> Result<(), ApplicationError> {
        self.records
            .write()
            .await
            .insert(record.code.clone(), record);
        Ok(())
    }

    async fn consume_frontend_session_code(
        &self,
        code: &FrontendSessionCode,
        now: OffsetDateTime,
    ) -> Result<Option<FrontendSessionCodeRecord>, ApplicationError> {
        let mut records = self.records.write().await;
        let Some(record) = records.get_mut(code) else {
            return Ok(None);
        };
        let previous = record.clone();
        record.consumed_at = Some(now);
        Ok(Some(previous))
    }
}

#[derive(Debug, Default)]
pub(super) struct InMemoryFrontendSessionStore {
    records: RwLock<HashMap<FrontendSessionToken, FrontendSessionRecord>>,
}

impl InMemoryFrontendSessionStore {
    pub(super) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl FrontendSessionStore for InMemoryFrontendSessionStore {
    async fn insert_frontend_session(
        &self,
        record: FrontendSessionRecord,
    ) -> Result<(), ApplicationError> {
        self.records
            .write()
            .await
            .insert(record.token.clone(), record);
        Ok(())
    }

    async fn get_frontend_session(
        &self,
        token: &FrontendSessionToken,
    ) -> Result<Option<FrontendSessionRecord>, ApplicationError> {
        Ok(self.records.read().await.get(token).cloned())
    }

    async fn delete_frontend_session(
        &self,
        token: &FrontendSessionToken,
    ) -> Result<(), ApplicationError> {
        self.records.write().await.remove(token);
        Ok(())
    }
}
