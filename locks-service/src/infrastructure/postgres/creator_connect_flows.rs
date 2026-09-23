use async_trait::async_trait;
use sqlx::types::Json;
use sqlx::{PgPool, Row};

use crate::application::errors::ApplicationError;
use crate::application::models::{
    CreatorConnectAuthorizationUrl, CreatorConnectFlowId, PendingCreatorConnectFlowRecord,
};
use crate::application::ports::CreatorConnectFlowStore;

/// Suffix of the companion row that holds a flow's grant authorization URL.
///
/// The grant URL lives in its own row of `pending_creator_connect_flows` instead of a new
/// column so the schema is unchanged: an image without grant support still starts against
/// this database, and it never reads a companion row because server-generated flow ids
/// contain no `.`.
const GRANT_COMPANION_SUFFIX: &str = ".grant";

fn grant_companion_flow_id(flow_id: &CreatorConnectFlowId) -> String {
    format!("{}{GRANT_COMPANION_SUFFIX}", flow_id.as_str())
}

fn is_grant_companion_flow_id(flow_id: &CreatorConnectFlowId) -> bool {
    flow_id.as_str().ends_with(GRANT_COMPANION_SUFFIX)
}

/// Postgres-backed store for short-lived pending creator connect flows.
#[derive(Debug, Clone)]
pub struct PostgresCreatorConnectFlowStore {
    pool: PgPool,
}

impl PostgresCreatorConnectFlowStore {
    /// Creates a store backed by the provided migrated Postgres pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CreatorConnectFlowStore for PostgresCreatorConnectFlowStore {
    async fn insert_pending_creator_connect_flow(
        &self,
        record: PendingCreatorConnectFlowRecord,
    ) -> Result<(), ApplicationError> {
        if is_grant_companion_flow_id(&record.flow_id) {
            return Err(ApplicationError::Storage {
                message: "pending creator connect flow id is reserved".to_owned(),
            });
        }
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let mut rows = vec![(
            record.flow_id.as_str().to_owned(),
            record.authorization_url.expose_url().to_owned(),
        )];
        if let Some(grant_authorization_url) = &record.grant_authorization_url {
            rows.push((
                grant_companion_flow_id(&record.flow_id),
                grant_authorization_url.expose_url().to_owned(),
            ));
        }

        for (flow_id, authorization_url) in rows {
            let result = sqlx::query(
                "INSERT INTO pending_creator_connect_flows (
                    flow_id,
                    return_to,
                    state,
                    authorization_url,
                    requested_scopes,
                    created_at,
                    expires_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (flow_id) DO NOTHING",
            )
            .bind(flow_id)
            .bind(&record.return_to)
            .bind(&record.state)
            .bind(authorization_url)
            .bind(Json(&record.requested_scopes))
            .bind(record.created_at)
            .bind(record.expires_at)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;

            if result.rows_affected() == 0 {
                return Err(ApplicationError::DuplicateRecord {
                    record: "pending_creator_connect_flow",
                });
            }
        }

        transaction.commit().await.map_err(storage_error)?;
        Ok(())
    }

    async fn get_pending_creator_connect_flow(
        &self,
        flow_id: &CreatorConnectFlowId,
    ) -> Result<Option<PendingCreatorConnectFlowRecord>, ApplicationError> {
        if is_grant_companion_flow_id(flow_id) {
            return Ok(None);
        }
        let row = sqlx::query(
            "SELECT
                flow.flow_id,
                flow.return_to,
                flow.state,
                flow.authorization_url,
                grant_flow.authorization_url AS grant_authorization_url,
                flow.requested_scopes,
                flow.created_at,
                flow.expires_at
            FROM pending_creator_connect_flows AS flow
            LEFT JOIN pending_creator_connect_flows AS grant_flow
                ON grant_flow.flow_id = $2
            WHERE flow.flow_id = $1",
        )
        .bind(flow_id.as_str())
        .bind(grant_companion_flow_id(flow_id))
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        row.map(row_to_record).transpose()
    }

    async fn delete_pending_creator_connect_flow(
        &self,
        flow_id: &CreatorConnectFlowId,
    ) -> Result<(), ApplicationError> {
        if is_grant_companion_flow_id(flow_id) {
            return Ok(());
        }
        sqlx::query("DELETE FROM pending_creator_connect_flows WHERE flow_id IN ($1, $2)")
            .bind(flow_id.as_str())
            .bind(grant_companion_flow_id(flow_id))
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(())
    }
}

fn row_to_record(
    row: sqlx::postgres::PgRow,
) -> Result<PendingCreatorConnectFlowRecord, ApplicationError> {
    let flow_id =
        CreatorConnectFlowId::new(row.try_get::<String, _>("flow_id").map_err(storage_error)?);
    let requested_scopes = row
        .try_get::<Json<Vec<String>>, _>("requested_scopes")
        .map_err(storage_error)?
        .0;

    Ok(PendingCreatorConnectFlowRecord {
        flow_id,
        return_to: row.try_get("return_to").map_err(storage_error)?,
        state: row.try_get("state").map_err(storage_error)?,
        authorization_url: CreatorConnectAuthorizationUrl::new(
            row.try_get::<String, _>("authorization_url")
                .map_err(storage_error)?,
        ),
        grant_authorization_url: row
            .try_get::<Option<String>, _>("grant_authorization_url")
            .map_err(storage_error)?
            .map(CreatorConnectAuthorizationUrl::new),
        requested_scopes,
        created_at: row.try_get("created_at").map_err(storage_error)?,
        expires_at: row.try_get("expires_at").map_err(storage_error)?,
    })
}

fn storage_error(error: sqlx::Error) -> ApplicationError {
    ApplicationError::Storage {
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::PostgresCreatorConnectFlowStore;
    use crate::application::errors::ApplicationError;
    use crate::application::models::{
        CreatorConnectAuthorizationUrl, CreatorConnectFlowId, PendingCreatorConnectFlowRecord,
    };
    use crate::application::ports::CreatorConnectFlowStore;
    use crate::infrastructure::postgres::testing::TestDatabase;
    use time::macros::datetime;

    #[tokio::test]
    async fn insert_get_delete_and_missing_semantics_match_port_contract() {
        let database = TestDatabase::create().await;
        let store = PostgresCreatorConnectFlowStore::new(database.pool().clone());
        let flow_id = CreatorConnectFlowId::new("flow-123");
        let record = pending_flow_record(flow_id.clone());

        assert_eq!(
            store
                .get_pending_creator_connect_flow(&flow_id)
                .await
                .unwrap(),
            None
        );

        store
            .insert_pending_creator_connect_flow(record.clone())
            .await
            .unwrap();
        assert_eq!(
            store
                .get_pending_creator_connect_flow(&flow_id)
                .await
                .unwrap(),
            Some(record.clone())
        );

        store
            .delete_pending_creator_connect_flow(&flow_id)
            .await
            .unwrap();
        store
            .delete_pending_creator_connect_flow(&flow_id)
            .await
            .unwrap();
        assert_eq!(
            store
                .get_pending_creator_connect_flow(&flow_id)
                .await
                .unwrap(),
            None
        );

        database.cleanup().await;
    }

    #[tokio::test]
    async fn record_survives_store_recreation_and_debug_output_redacts_authorization_url() {
        let database = TestDatabase::create().await;
        let original_store = PostgresCreatorConnectFlowStore::new(database.pool().clone());
        let recreated_store = PostgresCreatorConnectFlowStore::new(database.pool().clone());
        let flow_id = CreatorConnectFlowId::new("flow-123");
        let authorization_url = "pubkyauth://secret-flow-token";
        let record = PendingCreatorConnectFlowRecord {
            authorization_url: CreatorConnectAuthorizationUrl::new(authorization_url),
            ..pending_flow_record(flow_id.clone())
        };

        original_store
            .insert_pending_creator_connect_flow(record.clone())
            .await
            .unwrap();

        let loaded = recreated_store
            .get_pending_creator_connect_flow(&flow_id)
            .await
            .unwrap()
            .expect("stored pending flow");
        assert_eq!(loaded, record);
        assert_eq!(loaded.authorization_url.expose_url(), authorization_url);
        assert!(!format!("{loaded:?}").contains(authorization_url));

        database.cleanup().await;
    }

    #[tokio::test]
    async fn grant_url_round_trips_in_companion_row_without_schema_change() {
        let database = TestDatabase::create().await;
        let store = PostgresCreatorConnectFlowStore::new(database.pool().clone());
        let flow_id = CreatorConnectFlowId::new("flow-123");
        let record = PendingCreatorConnectFlowRecord {
            grant_authorization_url: Some(CreatorConnectAuthorizationUrl::new(
                "pubkyauth://signin_grant?secret-grant-token",
            )),
            ..pending_flow_record(flow_id.clone())
        };

        store
            .insert_pending_creator_connect_flow(record.clone())
            .await
            .unwrap();

        let loaded = store
            .get_pending_creator_connect_flow(&flow_id)
            .await
            .unwrap()
            .expect("stored pending flow");
        assert_eq!(loaded, record);
        assert!(!format!("{loaded:?}").contains("secret-grant-token"));

        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT flow_id, authorization_url FROM pending_creator_connect_flows ORDER BY flow_id",
        )
        .fetch_all(database.pool())
        .await
        .unwrap();
        assert_eq!(
            rows,
            vec![
                (
                    "flow-123".to_owned(),
                    "pubkyauth://secret-flow-token".to_owned()
                ),
                (
                    "flow-123.grant".to_owned(),
                    "pubkyauth://signin_grant?secret-grant-token".to_owned()
                ),
            ]
        );
        assert_eq!(
            store
                .get_pending_creator_connect_flow(&CreatorConnectFlowId::new("flow-123.grant"))
                .await
                .unwrap(),
            None,
            "a companion row is never a pending flow of its own"
        );

        store
            .delete_pending_creator_connect_flow(&flow_id)
            .await
            .unwrap();
        let remaining: i64 =
            sqlx::query_scalar("SELECT count(*) FROM pending_creator_connect_flows")
                .fetch_one(database.pool())
                .await
                .unwrap();
        assert_eq!(remaining, 0);

        let reserved = store
            .insert_pending_creator_connect_flow(pending_flow_record(CreatorConnectFlowId::new(
                "flow-123.grant",
            )))
            .await
            .unwrap_err();
        assert!(matches!(reserved, ApplicationError::Storage { .. }));

        database.cleanup().await;
    }

    fn pending_flow_record(flow_id: CreatorConnectFlowId) -> PendingCreatorConnectFlowRecord {
        PendingCreatorConnectFlowRecord {
            flow_id,
            return_to: "https://app.example/locks/callback".to_owned(),
            state: "state-123".to_owned(),
            authorization_url: CreatorConnectAuthorizationUrl::new("pubkyauth://secret-flow-token"),
            grant_authorization_url: None,
            requested_scopes: vec![
                "/pub/locks.app/:rw".to_owned(),
                "/priv/locks.app/:rw".to_owned(),
            ],
            created_at: datetime!(2026-05-29 12:00:00 UTC),
            expires_at: datetime!(2026-05-29 12:05:00 UTC),
        }
    }
}
