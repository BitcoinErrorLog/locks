use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use locks_core::ids::CreatorPubky;
use pubky::{
    AuthFlowKind, Capability, ClientId, DelegatedGrantAuthFlowState, DelegatedGrantCredentialState,
    DelegatedSignFn, GrantClaims, GrantCredential, Keypair, POP_JWS_TYP, PubkyGrantAuthFlow,
    PubkyHttpClient, PubkySession, PublicKey, delegated_sign_callback,
};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use url::Url;

use crate::application::errors::ApplicationError;
use crate::application::models::{
    CreatorAuthoritySecret, CreatorConnectAuthorizationUrl, GrantCreatorConnectFlowApproval,
    GrantPopKeyId,
};
use crate::application::ports::GrantCreatorConnectFlowClient;
use crate::infrastructure::pubky::legacy_connect_flow::{
    creator_from_pubky_public_key_z32, requested_scopes_to_capabilities,
};
use crate::infrastructure::pubky::legacy_creator_authority::classify_homeserver_restore_error;

/// BLAKE3 `derive_key` context for Lock Server grant PoP keys. Changing it orphans every
/// stored grant authority.
const GRANT_POP_KEY_CONTEXT: &str = "pubky-locks 2026-09-23 creator grant PoP key v1";
const GRANT_STATE_VERSION: u64 = 1;
const GRANT_STATE_FIELDS: [&str; 5] = ["client_pk", "grant_jws", "homeserver", "key_id", "v"];

/// Lock-Server-held keys that sign grant Proof-of-Possession proofs.
///
/// Each key is derived from the Lock Server signing seed (`credentials.lock_server_secret_key`)
/// and a non-secret [`GrantPopKeyId`]. The private half exists only in process memory: the
/// authority store keeps the key id and public key inside [`DelegatedGrantCredentialState`],
/// and the SDK only ever sees a [`DelegatedSignFn`], so no grant can export a local secret.
/// The signer refuses any input that is not a `pubky-pop` JWS.
#[derive(Clone)]
pub struct LockServerGrantPopKeys {
    seed: Arc<[u8; 32]>,
}

impl fmt::Debug for LockServerGrantPopKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LockServerGrantPopKeys")
            .field(&"<redacted>")
            .finish()
    }
}

impl LockServerGrantPopKeys {
    /// Creates the key source from the Lock Server signing seed.
    pub fn from_lock_server_seed(seed: [u8; 32]) -> Self {
        Self {
            seed: Arc::new(seed),
        }
    }

    fn keypair(&self, key_id: &GrantPopKeyId) -> Keypair {
        let mut hasher = blake3::Hasher::new_derive_key(GRANT_POP_KEY_CONTEXT);
        hasher.update(self.seed.as_ref());
        hasher.update(key_id.as_str().as_bytes());
        Keypair::from_secret(hasher.finalize().as_bytes())
    }

    /// Public key bound as the grant `cnf` for `key_id`.
    pub fn public_key(&self, key_id: &GrantPopKeyId) -> PublicKey {
        self.keypair(key_id).public_key()
    }

    /// Delegated signing callback for `key_id`.
    pub fn signer(&self, key_id: &GrantPopKeyId) -> DelegatedSignFn {
        let keypair = self.keypair(key_id);
        delegated_sign_callback(move |signing_input: String| {
            let signature = sign_pop_signing_input(&keypair, &signing_input);
            async move { signature }
        })
    }
}

fn sign_pop_signing_input(keypair: &Keypair, signing_input: &str) -> pubky::Result<Vec<u8>> {
    if !is_pop_signing_input(signing_input) {
        return Err(pubky::errors::AuthError::Validation(
            "Lock Server grant key only signs pubky-pop proofs".to_owned(),
        )
        .into());
    }
    Ok(keypair.sign(signing_input.as_bytes()).to_bytes().to_vec())
}

fn is_pop_signing_input(signing_input: &str) -> bool {
    let Some((header, claims)) = signing_input.split_once('.') else {
        return false;
    };
    if claims.is_empty() || claims.contains('.') {
        return false;
    }
    let Ok(header) = URL_SAFE_NO_PAD.decode(header) else {
        return false;
    };
    let Ok(header) = serde_json::from_slice::<Value>(&header) else {
        return false;
    };
    header.get("alg").and_then(Value::as_str) == Some("EdDSA")
        && header.get("typ").and_then(Value::as_str) == Some(POP_JWS_TYP)
}

/// Pubky SDK-backed grant creator connect-flow client.
#[derive(Debug, Clone)]
pub struct PubkyGrantCreatorConnectFlowClient {
    client: PubkyHttpClient,
    auth_relay: Option<Url>,
    client_id: ClientId,
    pop_keys: LockServerGrantPopKeys,
}

impl PubkyGrantCreatorConnectFlowClient {
    /// Creates a grant connect-flow adapter. `client_id` is the Lock Server's public
    /// hostname, shown to the signer as display identity. `auth_relay` overrides the SDK
    /// default relay inbox, matching the legacy connect client.
    pub fn new(
        client: PubkyHttpClient,
        auth_relay: Option<Url>,
        client_id: ClientId,
        pop_keys: LockServerGrantPopKeys,
    ) -> Self {
        Self {
            client,
            auth_relay,
            client_id,
            pop_keys,
        }
    }
}

#[async_trait]
impl GrantCreatorConnectFlowClient for PubkyGrantCreatorConnectFlowClient {
    async fn start_grant_creator_connect_flow(
        &self,
        requested_scopes: &[String],
        pop_key_id: &GrantPopKeyId,
    ) -> Result<CreatorConnectAuthorizationUrl, ApplicationError> {
        let capabilities = requested_scopes_to_capabilities(requested_scopes)?;
        let mut builder = PubkyGrantAuthFlow::builder(
            &capabilities,
            AuthFlowKind::signin(),
            self.client_id.clone(),
        )
        .client(self.client.clone())
        .delegated_client_signer(
            pop_key_id.as_str().to_owned(),
            self.pop_keys.public_key(pop_key_id),
            self.pop_keys.signer(pop_key_id),
        );
        if let Some(auth_relay) = &self.auth_relay {
            builder = builder.relay(auth_relay.clone());
        }
        let flow = builder
            .start()
            .map_err(|_| grant_connect_flow_error("failed to start grant creator connect flow"))?;
        Ok(CreatorConnectAuthorizationUrl::new(
            flow.authorization_url().to_string(),
        ))
    }

    async fn await_grant_creator_connect_flow_approval(
        &self,
        authorization_url: &CreatorConnectAuthorizationUrl,
        pop_key_id: &GrantPopKeyId,
        requested_scopes: &[String],
    ) -> Result<GrantCreatorConnectFlowApproval, ApplicationError> {
        let expected_client_pk = self.pop_keys.public_key(pop_key_id);
        let flow = PubkyGrantAuthFlow::restore_delegated(
            DelegatedGrantAuthFlowState {
                authorization_url: authorization_url.expose_url().to_owned(),
                key_id: pop_key_id.as_str().to_owned(),
                client_pk: expected_client_pk.clone(),
            },
            self.client.clone(),
            self.pop_keys.signer(pop_key_id),
        )
        .map_err(|_| grant_connect_flow_error("failed to resume grant creator connect flow"))?;
        let credential = flow.await_credential().await.map_err(|_| {
            grant_connect_flow_error("grant creator connect flow approval failed or expired")
        })?;
        let state = credential
            .export_delegated_restore_state()
            .await
            .ok_or_else(|| {
                grant_connect_flow_error("grant creator connect flow did not use a delegated key")
            })?;
        let session_pubky =
            PubkySession::from_grant_credential(self.client.clone(), credential).public_key();

        grant_approval_from_parts(
            state,
            &session_pubky,
            &self.client_id,
            &expected_client_pk,
            requested_scopes,
        )
    }
}

/// Validates an approved grant and converts it into creator-authority state.
///
/// The creator is the grant issuer, and the homeserver session must belong to that same
/// issuer. The grant must name this Lock Server's client id, bind the Lock Server PoP key,
/// and cover every requested scope.
fn grant_approval_from_parts(
    state: DelegatedGrantCredentialState,
    session_pubky: &PublicKey,
    expected_client_id: &ClientId,
    expected_client_pk: &PublicKey,
    requested_scopes: &[String],
) -> Result<GrantCreatorConnectFlowApproval, ApplicationError> {
    let claims = GrantClaims::decode(&state.grant_jws)
        .map_err(|_| grant_connect_flow_error("grant creator connect flow returned no grant"))?;
    if &claims.iss != session_pubky {
        return Err(grant_connect_flow_error(
            "grant issuer does not match the homeserver session",
        ));
    }
    if &claims.client_id != expected_client_id {
        return Err(grant_connect_flow_error(
            "grant names a different client id",
        ));
    }
    if &claims.cnf != expected_client_pk || &state.client_pk != expected_client_pk {
        return Err(grant_connect_flow_error(
            "grant is not bound to the Lock Server key",
        ));
    }
    let requested = requested_scopes_to_capabilities(requested_scopes)?;
    if !requested
        .iter()
        .all(|required| grant_covers(&claims.caps, required))
    {
        return Err(grant_connect_flow_error(
            "grant does not cover the requested scopes",
        ));
    }
    let creator = creator_from_pubky_public_key_z32(&claims.iss.z32())?;
    let grant_expires_at = i64::try_from(claims.exp)
        .ok()
        .and_then(|exp| OffsetDateTime::from_unix_timestamp(exp).ok())
        .ok_or_else(|| grant_connect_flow_error("grant expiry is out of range"))?;

    Ok(GrantCreatorConnectFlowApproval {
        creator,
        grant_state: encode_grant_state(&state),
        granted_scopes: claims.caps.iter().map(ToString::to_string).collect(),
        grant_expires_at,
    })
}

fn grant_covers(granted: &[Capability], required: &Capability) -> bool {
    granted.iter().any(|capability| {
        capability.scope_covers_path(required.scope())
            && required
                .actions()
                .iter()
                .all(|action| capability.actions().contains(action))
    })
}

/// Serializes delegated grant restore state for the creator-authority secret column.
///
/// The fields are exactly those of [`DelegatedGrantCredentialState`]; none is a private key.
pub fn encode_grant_state(state: &DelegatedGrantCredentialState) -> CreatorAuthoritySecret {
    CreatorAuthoritySecret::new(
        json!({
            "v": GRANT_STATE_VERSION,
            "grant_jws": state.grant_jws,
            "homeserver": state.homeserver_pk.z32(),
            "key_id": state.key_id,
            "client_pk": state.client_pk.z32(),
        })
        .to_string(),
    )
}

/// Parses state produced by [`encode_grant_state`]. Unknown or missing fields are rejected.
pub fn decode_grant_state(
    secret: &CreatorAuthoritySecret,
) -> Result<DelegatedGrantCredentialState, ApplicationError> {
    let object: Map<String, Value> =
        serde_json::from_str(secret.expose_secret()).map_err(|_| invalid_grant_state())?;
    let mut fields: Vec<&str> = object.keys().map(String::as_str).collect();
    fields.sort_unstable();
    if fields != GRANT_STATE_FIELDS
        || object.get("v").and_then(Value::as_u64) != Some(GRANT_STATE_VERSION)
    {
        return Err(invalid_grant_state());
    }
    let text = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(invalid_grant_state)
    };
    let public_key =
        |name: &str| PublicKey::try_from_z32(text(name)?).map_err(|_| invalid_grant_state());

    Ok(DelegatedGrantCredentialState {
        grant_jws: text("grant_jws")?.to_owned(),
        homeserver_pk: public_key("homeserver")?,
        key_id: text("key_id")?.to_owned(),
        client_pk: public_key("client_pk")?,
    })
}

/// Restores a grant-backed session from a stored `Grant` authority secret with
/// [`GrantCredential::import_delegated_state`], which exchanges the grant and a fresh PoP
/// proof for a new bearer.
pub async fn restore_grant_session(
    client: &PubkyHttpClient,
    pop_keys: &LockServerGrantPopKeys,
    secret: &CreatorAuthoritySecret,
) -> Result<PubkySession, ApplicationError> {
    let state = decode_grant_state(secret)?;
    let key_id = GrantPopKeyId::new(state.key_id.clone());
    if state.client_pk != pop_keys.public_key(&key_id) {
        return Err(grant_restore_error());
    }
    let credential =
        GrantCredential::import_delegated_state(state, client, pop_keys.signer(&key_id))
            .await
            .map_err(|error| classify_homeserver_restore_error(&error, grant_restore_error))?;
    Ok(PubkySession::from_grant_credential(
        client.clone(),
        credential,
    ))
}

/// Restores a stored grant and requires its session to belong to `creator`.
pub async fn restore_grant_session_for_creator(
    client: &PubkyHttpClient,
    pop_keys: &LockServerGrantPopKeys,
    creator: &CreatorPubky,
    secret: &CreatorAuthoritySecret,
) -> Result<PubkySession, ApplicationError> {
    let session = restore_grant_session(client, pop_keys, secret).await?;
    let restored = creator_from_pubky_public_key_z32(&session.public_key().z32())?;
    if &restored != creator {
        return Err(ApplicationError::CreatorAuthorityRefused);
    }
    Ok(session)
}

fn grant_connect_flow_error(message: &'static str) -> ApplicationError {
    ApplicationError::CreatorAuthoritySecret {
        message: message.to_owned(),
    }
}

fn invalid_grant_state() -> ApplicationError {
    ApplicationError::CreatorAuthoritySecret {
        message: "invalid stored grant creator authority".to_owned(),
    }
}

fn grant_restore_error() -> ApplicationError {
    ApplicationError::CreatorAuthoritySecret {
        message: "failed to restore grant creator authority".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use pubky::{
        Capability, ClientId, DelegatedGrantCredentialState, GRANT_JWS_TYP, GrantClaims, GrantId,
        Keypair, POP_JWS_TYP, PopNonce, PopProofClaims, PublicKey,
    };
    use pubky_common::auth::jws::jws_signing_input;
    use url::Url;

    use super::{
        LockServerGrantPopKeys, PubkyGrantCreatorConnectFlowClient, decode_grant_state,
        encode_grant_state, grant_approval_from_parts, restore_grant_session,
        sign_pop_signing_input,
    };
    use crate::application::errors::ApplicationError;
    use crate::application::models::{CreatorAuthoritySecret, CreatorConnectFlowId, GrantPopKeyId};
    use crate::application::ports::{
        GrantCreatorConnectFlowClient, LegacyCreatorConnectFlowClient,
    };
    use crate::infrastructure::pubky::PubkyLegacyCreatorConnectFlowClient;

    const SEED: [u8; 32] = [42; 32];
    const CLIENT_ID: &str = "locks.example";

    fn keys() -> LockServerGrantPopKeys {
        LockServerGrantPopKeys::from_lock_server_seed(SEED)
    }

    fn key_id() -> GrantPopKeyId {
        GrantPopKeyId::for_connect_flow(&CreatorConnectFlowId::new("flow-123"))
    }

    fn requested_scopes() -> Vec<String> {
        vec![
            "/pub/locks.app/:rw".to_owned(),
            "/priv/locks.app/:rw".to_owned(),
        ]
    }

    fn signed_state(
        issuer: &Keypair,
        client_id: &str,
        cnf: PublicKey,
        caps: &str,
    ) -> DelegatedGrantCredentialState {
        let claims = GrantClaims {
            iss: issuer.public_key(),
            client_id: ClientId::new(client_id).unwrap(),
            caps: caps
                .split(',')
                .map(|cap| Capability::from_str(cap).unwrap())
                .collect(),
            cnf: cnf.clone(),
            jti: GrantId::generate(),
            iat: 1_790_000_000,
            exp: 1_792_592_000,
        };
        DelegatedGrantCredentialState {
            grant_jws: claims.sign(issuer, GRANT_JWS_TYP),
            homeserver_pk: Keypair::random().public_key(),
            key_id: key_id().as_str().to_owned(),
            client_pk: cnf,
        }
    }

    fn approval(
        state: DelegatedGrantCredentialState,
        session_pubky: &PublicKey,
    ) -> Result<crate::application::models::GrantCreatorConnectFlowApproval, ApplicationError> {
        grant_approval_from_parts(
            state,
            session_pubky,
            &ClientId::new(CLIENT_ID).unwrap(),
            &keys().public_key(&key_id()),
            &requested_scopes(),
        )
    }

    #[test]
    fn grant_pop_keys_are_stable_per_key_id_and_distinct_across_ids_and_seeds() {
        let flow_a = key_id();
        let flow_b = GrantPopKeyId::for_connect_flow(&CreatorConnectFlowId::new("flow-456"));

        assert_eq!(keys().public_key(&flow_a), keys().public_key(&flow_a));
        assert_ne!(keys().public_key(&flow_a), keys().public_key(&flow_b));
        assert_ne!(
            keys().public_key(&flow_a),
            LockServerGrantPopKeys::from_lock_server_seed([7; 32]).public_key(&flow_a)
        );
        assert_ne!(
            keys().public_key(&flow_a),
            Keypair::from_secret(&SEED).public_key(),
            "the grant key is not the Lock Server identity key"
        );
        assert!(!format!("{:?}", keys()).contains("42"));
    }

    #[test]
    fn grant_pop_key_signs_pop_proofs_only() {
        let keypair = keys().keypair(&key_id());
        let pop = jws_signing_input(
            POP_JWS_TYP,
            &PopProofClaims {
                aud: Keypair::random().public_key(),
                gid: GrantId::generate(),
                nonce: PopNonce::generate(),
                iat: 1_790_000_000,
            },
        );
        assert_eq!(
            sign_pop_signing_input(&keypair, &pop).unwrap(),
            keypair.sign(pop.as_bytes()).to_bytes().to_vec()
        );

        let grant = jws_signing_input(GRANT_JWS_TYP, &serde_json::json!({"caps": "/:rw"}));
        let unsigned_header = format!(
            "{}.e30",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"pubky-pop"}"#)
        );
        for rejected in [
            grant.as_str(),
            unsigned_header.as_str(),
            "not-a-jws",
            "e30.e30.e30",
            "",
        ] {
            assert!(
                sign_pop_signing_input(&keypair, rejected).is_err(),
                "{rejected}"
            );
        }
    }

    #[test]
    fn grant_connect_stores_grant_record_without_private_key() {
        let pop_keypair = keys().keypair(&key_id());
        let state = signed_state(
            &Keypair::random(),
            CLIENT_ID,
            pop_keypair.public_key(),
            "/priv/locks.app/:rw,/pub/locks.app/:rw",
        );

        let stored = encode_grant_state(&state);
        let text = stored.expose_secret();
        let object: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(text).unwrap();
        let mut fields: Vec<&str> = object.keys().map(String::as_str).collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            ["client_pk", "grant_jws", "homeserver", "key_id", "v"]
        );

        for secret in [pop_keypair.secret(), SEED] {
            assert!(!text.contains(&URL_SAFE_NO_PAD.encode(secret)));
            assert!(!text.contains(&base64::engine::general_purpose::STANDARD.encode(secret)));
            let hex: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
            assert!(!text.contains(&hex));
        }
        assert!(!text.starts_with("pubky-grant-credential-"));
        assert!(!format!("{stored:?}").contains(&state.grant_jws));

        assert_eq!(decode_grant_state(&stored).unwrap(), state);
    }

    #[test]
    fn stored_grant_state_rejects_unknown_missing_and_foreign_formats() {
        let state = signed_state(
            &Keypair::random(),
            CLIENT_ID,
            keys().public_key(&key_id()),
            "/priv/locks.app/:rw,/pub/locks.app/:rw",
        );
        let stored = encode_grant_state(&state);
        let mut object: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(stored.expose_secret()).unwrap();

        let mut with_secret = object.clone();
        with_secret.insert("client_key_secret".to_owned(), "AAAA".into());
        let mut wrong_version = object.clone();
        wrong_version.insert("v".to_owned(), 2.into());
        object.remove("key_id");

        for rejected in [
            serde_json::Value::Object(with_secret).to_string(),
            serde_json::Value::Object(wrong_version).to_string(),
            serde_json::Value::Object(object).to_string(),
            "pubky-grant-credential-v1:hs:secret:jws".to_owned(),
            "legacy-cookie-session-secret".to_owned(),
        ] {
            assert!(
                decode_grant_state(&CreatorAuthoritySecret::new(rejected.clone())).is_err(),
                "{rejected}"
            );
        }
    }

    #[test]
    fn grant_connect_creator_must_equal_grant_issuer() {
        let issuer = Keypair::random();
        let state = signed_state(
            &issuer,
            CLIENT_ID,
            keys().public_key(&key_id()),
            "/priv/locks.app/:rw,/pub/locks.app/:rw",
        );

        let error = approval(state.clone(), &Keypair::random().public_key()).unwrap_err();
        assert_eq!(
            error,
            ApplicationError::CreatorAuthoritySecret {
                message: "grant issuer does not match the homeserver session".to_owned()
            }
        );

        let approved = approval(state, &issuer.public_key()).unwrap();
        assert_eq!(
            approved.creator.to_string(),
            format!("pubky{}", issuer.public_key().z32())
        );
        assert_eq!(
            approved.granted_scopes,
            vec!["/priv/locks.app/:rw", "/pub/locks.app/:rw"]
        );
        assert_eq!(
            approved.grant_expires_at,
            time::OffsetDateTime::from_unix_timestamp(1_792_592_000).unwrap()
        );
    }

    #[test]
    fn grant_approval_rejects_foreign_client_id_key_and_narrow_caps() {
        let issuer = Keypair::random();
        let pop = keys().public_key(&key_id());
        let full = "/priv/locks.app/:rw,/pub/locks.app/:rw";

        for (state, message) in [
            (
                signed_state(&issuer, "evil.example", pop.clone(), full),
                "grant names a different client id",
            ),
            (
                signed_state(&issuer, CLIENT_ID, Keypair::random().public_key(), full),
                "grant is not bound to the Lock Server key",
            ),
            (
                signed_state(&issuer, CLIENT_ID, pop.clone(), "/pub/locks.app/:rw"),
                "grant does not cover the requested scopes",
            ),
            (
                signed_state(
                    &issuer,
                    CLIENT_ID,
                    pop.clone(),
                    "/priv/locks.app/:r,/pub/locks.app/:rw",
                ),
                "grant does not cover the requested scopes",
            ),
            (
                signed_state(
                    &issuer,
                    CLIENT_ID,
                    pop.clone(),
                    "/priv/locks.app-evil/:rw,/pub/locks.app/:rw",
                ),
                "grant does not cover the requested scopes",
            ),
        ] {
            assert_eq!(
                approval(state, &issuer.public_key()).unwrap_err(),
                ApplicationError::CreatorAuthoritySecret {
                    message: message.to_owned()
                }
            );
        }

        let broader = signed_state(&issuer, CLIENT_ID, pop, "/priv/:rw,/pub/:rw");
        assert!(approval(broader, &issuer.public_key()).is_ok());
    }

    #[tokio::test]
    async fn grant_and_cookie_connect_request_identical_caps() {
        let relay: Url = "http://localhost:15412/inbox/".parse().unwrap();
        let cookie = PubkyLegacyCreatorConnectFlowClient::new_with_auth_relay(
            pubky::Pubky::testnet().unwrap(),
            relay.clone(),
        );
        let grant = PubkyGrantCreatorConnectFlowClient::new(
            pubky::PubkyHttpClient::testnet().unwrap(),
            Some(relay),
            ClientId::new(CLIENT_ID).unwrap(),
            keys(),
        );

        let cookie_url = cookie
            .start_legacy_creator_connect_flow(&requested_scopes())
            .await
            .unwrap();
        let grant_url = grant
            .start_grant_creator_connect_flow(&requested_scopes(), &key_id())
            .await
            .unwrap();

        let cookie_url = Url::parse(cookie_url.expose_url()).unwrap();
        let grant_url = Url::parse(grant_url.expose_url()).unwrap();
        let param = |url: &Url, name: &str| {
            url.query_pairs()
                .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
        };
        let names = |url: &Url| {
            let mut names: Vec<String> =
                url.query_pairs().map(|(key, _)| key.into_owned()).collect();
            names.sort();
            names
        };

        assert_eq!(cookie_url.scheme(), "pubkyauth");
        assert_eq!(cookie_url.host_str(), Some("signin"));
        assert_eq!(names(&cookie_url), ["caps", "relay", "secret"]);
        assert_eq!(grant_url.scheme(), "pubkyauth");
        assert_eq!(grant_url.host_str(), Some("signin_grant"));
        assert_eq!(names(&grant_url), ["caps", "cid", "cpk", "relay", "secret"]);
        assert_eq!(
            param(&cookie_url, "caps").as_deref(),
            Some("/pub/locks.app/:rw,/priv/locks.app/:rw")
        );
        assert_eq!(param(&grant_url, "caps"), param(&cookie_url, "caps"));
        assert_eq!(param(&grant_url, "relay"), param(&cookie_url, "relay"));
        assert_eq!(param(&grant_url, "cid").as_deref(), Some(CLIENT_ID));
        assert_eq!(
            param(&grant_url, "cpk"),
            Some(keys().public_key(&key_id()).z32())
        );
        assert_ne!(param(&grant_url, "secret"), param(&cookie_url, "secret"));
    }

    #[tokio::test]
    async fn restore_refuses_state_bound_to_another_key_before_network() {
        let state = signed_state(
            &Keypair::random(),
            CLIENT_ID,
            Keypair::random().public_key(),
            "/priv/locks.app/:rw,/pub/locks.app/:rw",
        );

        let error = restore_grant_session(
            &pubky::PubkyHttpClient::testnet().unwrap(),
            &keys(),
            &encode_grant_state(&state),
        )
        .await
        .unwrap_err();

        assert_eq!(
            error,
            ApplicationError::CreatorAuthoritySecret {
                message: "failed to restore grant creator authority".to_owned()
            }
        );
    }
}
