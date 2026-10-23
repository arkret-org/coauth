//! IVS storage over the surrounding cancellation-safe repository transaction.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::storage::third_party_invite::{PrivateInviteRecord, ThirdPartyInviteRepository};
use diesel::sql_types::{BigInt, Nullable, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension, RunQueryDsl};

use crate::DatabaseError;

/// Transaction-borrowed private IVS repository.
pub struct PgThirdPartyInviteRepository<'a, P = diesel_async::AsyncPgConnection> {
    conn: &'a mut P,
}
impl<'a, P: horme::GetConnection<Connection = diesel_async::AsyncPgConnection> + Sync>
    PgThirdPartyInviteRepository<'a, P>
{
    /// Borrow the current request transaction.
    pub fn new(conn: &'a mut P) -> Self {
        Self { conn }
    }
}

#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type=Text)]
    handle_digest: String,
    #[diesel(sql_type=Text)]
    issuer_digest: String,
    #[diesel(sql_type=Text)]
    realm_digest: String,
    #[diesel(sql_type=Text)]
    request_id: String,
    #[diesel(sql_type=Text)]
    intent_digest: String,
    #[diesel(sql_type=Text)]
    encrypted_record: String,
    #[diesel(sql_type=Nullable<Text>)]
    token_selector: Option<String>,
    #[diesel(sql_type=Text)]
    state: String,
    #[diesel(sql_type=Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type=Timestamptz)]
    activation_expires_at: DateTime<Utc>,
    #[diesel(sql_type=Nullable<Timestamptz>)]
    deliver_after: Option<DateTime<Utc>>,
}
impl From<Row> for PrivateInviteRecord {
    fn from(r: Row) -> Self {
        Self {
            handle_digest: r.handle_digest,
            issuer_digest: r.issuer_digest,
            realm_digest: r.realm_digest,
            request_id: r.request_id,
            intent_digest: r.intent_digest,
            encrypted_record: r.encrypted_record,
            token_selector: r.token_selector,
            state: r.state,
            expires_at: r.expires_at,
            activation_expires_at: r.activation_expires_at,
            deliver_after: r.deliver_after,
        }
    }
}
#[derive(QueryableByName)]
struct Count {
    #[diesel(sql_type=BigInt)]
    count: i64,
}

#[async_trait]
impl<P: horme::GetConnection<Connection = diesel_async::AsyncPgConnection> + Sync>
    ThirdPartyInviteRepository for PgThirdPartyInviteRepository<'_, P>
{
    type Error = DatabaseError;
    async fn lock_namespace(&mut self, namespace: &str) -> Result<(), Self::Error> {
        sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 639331))")
            .bind::<Text, _>(namespace)
            .execute(self.conn)
            .await?;
        Ok(())
    }
    async fn find_request(
        &mut self,
        issuer: &str,
        request_id: &str,
    ) -> Result<Option<PrivateInviteRecord>, Self::Error> {
        Ok(sql_query("SELECT * FROM third_party_invite_private WHERE issuer_digest=$1 AND request_id=$2 FOR UPDATE")
            .bind::<Text,_>(issuer).bind::<Text,_>(request_id).get_result::<Row>(self.conn).await.optional()?.map(Into::into))
    }
    async fn find(&mut self, handle: &str) -> Result<Option<PrivateInviteRecord>, Self::Error> {
        Ok(
            sql_query("SELECT * FROM third_party_invite_private WHERE handle_digest=$1 FOR UPDATE")
                .bind::<Text, _>(handle)
                .get_result::<Row>(self.conn)
                .await
                .optional()?
                .map(Into::into),
        )
    }
    async fn find_token(
        &mut self,
        selector: &str,
    ) -> Result<Option<PrivateInviteRecord>, Self::Error> {
        Ok(
            sql_query(
                "SELECT * FROM third_party_invite_private WHERE token_selector=$1 FOR UPDATE",
            )
            .bind::<Text, _>(selector)
            .get_result::<Row>(self.conn)
            .await
            .optional()?
            .map(Into::into),
        )
    }
    async fn insert(&mut self, r: PrivateInviteRecord) -> Result<bool, Self::Error> {
        Ok(sql_query("INSERT INTO third_party_invite_private(handle_digest,issuer_digest,realm_digest,request_id,intent_digest,encrypted_record,token_selector,state,expires_at,activation_expires_at,deliver_after) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING")
            .bind::<Text,_>(r.handle_digest).bind::<Text,_>(r.issuer_digest).bind::<Text,_>(r.realm_digest)
            .bind::<Text,_>(r.request_id).bind::<Text,_>(r.intent_digest).bind::<Text,_>(r.encrypted_record)
            .bind::<Nullable<Text>,_>(r.token_selector).bind::<Text,_>(r.state).bind::<Timestamptz,_>(r.expires_at)
            .bind::<Timestamptz,_>(r.activation_expires_at).bind::<Nullable<Timestamptz>,_>(r.deliver_after)
            .execute(self.conn).await?==1)
    }
    async fn update(&mut self, r: PrivateInviteRecord) -> Result<(), Self::Error> {
        sql_query("UPDATE third_party_invite_private SET encrypted_record=$2, token_selector=$3, state=$4, deliver_after=$5 WHERE handle_digest=$1")
            .bind::<Text,_>(r.handle_digest).bind::<Text,_>(r.encrypted_record).bind::<Nullable<Text>,_>(r.token_selector)
            .bind::<Text,_>(r.state).bind::<Nullable<Timestamptz>,_>(r.deliver_after).execute(self.conn).await?;
        Ok(())
    }
    async fn unactivated_count(
        &mut self,
        issuer: &str,
        realm: &str,
        now: DateTime<Utc>,
    ) -> Result<i64, Self::Error> {
        Ok(sql_query("SELECT COUNT(*)::bigint AS count FROM third_party_invite_private WHERE issuer_digest=$1 AND realm_digest=$2 AND state='provisioned' AND activation_expires_at>$3")
            .bind::<Text,_>(issuer).bind::<Text,_>(realm).bind::<Timestamptz,_>(now).get_result::<Count>(self.conn).await?.count)
    }
    async fn take_rate(
        &mut self,
        bucket: &str,
        window: DateTime<Utc>,
        maximum: i64,
    ) -> Result<bool, Self::Error> {
        let rows=sql_query("INSERT INTO third_party_invite_rate(bucket,window_start,attempts) VALUES($1,$2,1) ON CONFLICT(bucket,window_start) DO UPDATE SET attempts=third_party_invite_rate.attempts+1 WHERE third_party_invite_rate.attempts<$3 RETURNING attempts AS count")
            .bind::<Text,_>(bucket).bind::<Timestamptz,_>(window).bind::<BigInt,_>(maximum).load::<Count>(self.conn).await?;
        Ok(!rows.is_empty())
    }
    async fn due(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<Option<PrivateInviteRecord>, Self::Error> {
        Ok(sql_query("SELECT * FROM third_party_invite_private WHERE deliver_after<=$1 OR (state='provisioned' AND activation_expires_at<=$1) OR (state='activated' AND expires_at<=$1) ORDER BY deliver_after NULLS FIRST FOR UPDATE SKIP LOCKED LIMIT 1")
            .bind::<Timestamptz,_>(now).get_result::<Row>(self.conn).await.optional()?.map(Into::into))
    }
}
