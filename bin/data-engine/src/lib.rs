//! Example of subscribing and listening for all contract events by `WebSocket` subscription.

use std::str::FromStr;

use alloy::{
    primitives::{address, Address},
    providers::{Provider, ProviderBuilder, WsConnect},
    pubsub::{ConnectionHandle, PubSubConnect},
    rpc::types::{BlockNumberOrTag, Filter},
    sol,
    sol_types::SolEvent,
    transports::{impl_future, TransportResult},
};
use backoff::ExponentialBackoff;
use eyre::Result;
use futures_util::stream::StreamExt;
use rift_sdk::bindings::RiftExchange;
use rift_sdk::bindings::Types::DepositVault;
use rift_sdk::bindings::Types::ProposedSwap;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use sqlx::types::Json;
use sqlx::Row;
use tracing;
use tracing_subscriber;

enum SwapStatus {
    PaymentPending,
    ChallengePeriod,
    Completed,
    LiquidityWithdrawn,
}

/*
TABLE otc_swaps (
    id                  BLOB(32)     NOT NULL PRIMARY KEY, -- 32-byte primary key
    depositor           BLOB(20)     NOT NULL,             -- 20 bytes for an EVM address
    recipient           BLOB(20)     NOT NULL,
    deposit_vault       TEXT         NOT NULL,  -- or JSON/BLOB if your DB supports JSON columns
    deposit_txid        BLOB(32)     NOT NULL,
    deposit_block_number BIGINT      NOT NULL,
    deposit_block_hash  BLOB(32)     NOT NULL,
    proposed_swaps      TEXT         NOT NULL,  -- JSON array of ProposedSwap
    proposed_swap_txids TEXT         NOT NULL,  -- JSON array of 32-byte TXIDs
    release_txid        BLOB(32),    -- optional
    withdraw_txid       BLOB(32)     -- optional
);
*/

#[derive(Debug, Clone)]
struct OTCSwap {
    pub id: [u8; 32],       // copied from depositVault.nonce  (primary key)
    pub depositor: Address, // copied from depositVault.owner
    pub recipient: Address, // copied from depositVault.specifiedPayoutAddress
    pub deposit_vault: DepositVault,
    pub deposit_txid: [u8; 32],
    pub deposit_block_number: u64,    // used for reorg detection
    pub deposit_block_hash: [u8; 32], // used for reorg detection
    pub proposed_swaps: Vec<ProposedSwap>,
    pub proposed_swap_txids: Vec<[u8; 32]>,
    pub release_txid: Option<[u8; 32]>,
    pub withdraw_txid: Option<[u8; 32]>,
}

impl OTCSwap {
    pub fn new(
        vault: &DepositVault,
        deposit_txid: [u8; 32],
        deposit_block_number: u64,
        deposit_block_hash: [u8; 32],
    ) -> Self {
        Self {
            id: vault.nonce.0,
            depositor: vault.ownerAddress,
            recipient: vault.specifiedPayoutAddress,
            deposit_vault: vault.clone(),
            deposit_txid,
            deposit_block_number,
            deposit_block_hash,
            proposed_swaps: vec![],
            proposed_swap_txids: vec![],
            release_txid: None,
            withdraw_txid: None,
        }
    }

    pub fn swap_status(&self) -> SwapStatus {
        if self.withdraw_txid.is_some() {
            SwapStatus::LiquidityWithdrawn
        } else if self.proposed_swaps.is_empty() {
            SwapStatus::PaymentPending
        } else if self.release_txid.is_none() {
            SwapStatus::ChallengePeriod
        } else {
            SwapStatus::Completed
        }
    }
}

/// Retrying websocket connection using exponential backoff
#[derive(Clone, Debug)]
pub struct RetryWsConnect(WsConnect);

impl PubSubConnect for RetryWsConnect {
    fn is_local(&self) -> bool {
        self.0.is_local()
    }

    fn connect(&self) -> impl_future!(<Output = TransportResult<ConnectionHandle>>) {
        self.0.connect()
    }

    async fn try_reconnect(&self) -> TransportResult<ConnectionHandle> {
        backoff::future::retry(ExponentialBackoff::default(), || async {
            Ok(self.0.try_reconnect().await?)
        })
        .await
    }
}

pub async fn run_data_engine(
    evm_rpc_websocket_url: &str,
    rift_exchange_address: &str,
    pool: &SqlitePool,
) -> Result<()> {
    // Create the provider.
    let ws = WsConnect::new(evm_rpc_websocket_url);
    let provider = ProviderBuilder::new().on_ws(ws).await?;

    // Create a filter to watch for events
    let rift_exchange_address = Address::from_str(rift_exchange_address)?;
    let filter = Filter::new()
        .address(rift_exchange_address)
        .from_block(BlockNumberOrTag::Latest);

    // Subscribe to logs.
    let sub = provider.subscribe_logs(&filter).await?;
    let mut stream = sub.into_stream();

    while let Some(log) = stream.next().await {
        match log.topic0() {
            // for either log, see if an existing OTCSwap exists for the given deposit nonce
            // before creating a brand new OTCSwap
            Some(&RiftExchange::VaultUpdated::SIGNATURE_HASH) => {
                let RiftExchange::VaultUpdated { vault } = log.log_decode()?.inner.data;
                todo!()
            }
            Some(&RiftExchange::SwapUpdated::SIGNATURE_HASH) => {
                let RiftExchange::SwapUpdated { swap } = log.log_decode()?.inner.data;
                todo!()
            }
            _ => (),
        }
    }

    Ok(())
}

/// Database model for OTCSwap
#[derive(Debug, Serialize, Deserialize)]
struct DbOTCSwap {
    id: Vec<u8>,
    depositor: String,
    recipient: String,
    deposit_vault: Json<DepositVault>,
    deposit_txid: Vec<u8>,
    deposit_block_number: i64, // SQLite uses i64 for INTEGER
    deposit_block_hash: Vec<u8>,
    proposed_swaps: Json<Vec<ProposedSwap>>,
    proposed_swap_txids: Json<Vec<Vec<u8>>>,
    release_txid: Option<Vec<u8>>,
    withdraw_txid: Option<Vec<u8>>,
}

impl From<&OTCSwap> for DbOTCSwap {
    fn from(swap: &OTCSwap) -> Self {
        Self {
            id: swap.id.to_vec(),
            depositor: format!("{:?}", swap.depositor),
            recipient: format!("{:?}", swap.recipient),
            deposit_vault: Json(swap.deposit_vault.clone()),
            deposit_txid: swap.deposit_txid.to_vec(),
            deposit_block_number: swap.deposit_block_number as i64,
            deposit_block_hash: swap.deposit_block_hash.to_vec(),
            proposed_swaps: Json(swap.proposed_swaps.clone()),
            proposed_swap_txids: Json(
                swap.proposed_swap_txids
                    .iter()
                    .map(|x| x.to_vec())
                    .collect(),
            ),
            release_txid: swap.release_txid.map(|x| x.to_vec()),
            withdraw_txid: swap.withdraw_txid.map(|x| x.to_vec()),
        }
    }
}

impl OTCSwap {
    async fn save(&self, pool: &SqlitePool) -> Result<()> {
        let db_swap = DbOTCSwap::from(self);

        sqlx::query(
            r#"
            INSERT INTO otc_swaps (
                id, depositor, recipient, deposit_vault, deposit_txid,
                deposit_block_number, deposit_block_hash, proposed_swaps,
                proposed_swap_txids, release_txid, withdraw_txid
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                proposed_swaps = excluded.proposed_swaps,
                proposed_swap_txids = excluded.proposed_swap_txids,
                release_txid = excluded.release_txid,
                withdraw_txid = excluded.withdraw_txid,
            "#,
        )
        .bind(&db_swap.id)
        .bind(&db_swap.depositor)
        .bind(&db_swap.recipient)
        .bind(&db_swap.deposit_vault.encode_to_string())
        .bind(&db_swap.deposit_txid)
        .bind(db_swap.deposit_block_number)
        .bind(&db_swap.deposit_block_hash)
        .bind(&db_swap.proposed_swaps.encode_to_string())
        .bind(&db_swap.proposed_swap_txids)
        .bind(&db_swap.release_txid)
        .bind(&db_swap.withdraw_txid)
        .execute(pool)
        .await?;

        Ok(())
    }

    async fn load(pool: &SqlitePool, id: &[u8; 32]) -> Result<Option<Self>> {
        let record = sqlx::query(
            r#"
            SELECT * FROM otc_swaps WHERE id = ?
            "#,
        )
        .bind(id.to_vec())
        .fetch_optional(pool)
        .await?;

        match record {
            Some(r) => {
                let deposit_vault: DepositVault = serde_json::from_str(r.get("deposit_vault"))?;
                let proposed_swaps: Vec<ProposedSwap> =
                    serde_json::from_str(r.get("proposed_swaps"))?;
                let proposed_swap_txids: Vec<Vec<u8>> =
                    serde_json::from_str(r.get("proposed_swap_txids"))?;

                Ok(Some(OTCSwap {
                    id: r
                        .get::<Vec<u8>, _>("id")
                        .try_into()
                        .map_err(|_| eyre::eyre!("Invalid id length"))?,
                    depositor: Address::from_str(&r.get::<String, _>("depositor"))?,
                    recipient: Address::from_str(&r.get::<String, _>("recipient"))?,
                    deposit_vault,
                    deposit_txid: r
                        .get::<Vec<u8>, _>("deposit_txid")
                        .try_into()
                        .map_err(|_| eyre::eyre!("Invalid txid length"))?,
                    deposit_block_number: r.get::<i64, _>("deposit_block_number") as u64,
                    deposit_block_hash: r
                        .get::<Vec<u8>, _>("deposit_block_hash")
                        .try_into()
                        .map_err(|_| eyre::eyre!("Invalid block hash length"))?,
                    proposed_swaps,
                    proposed_swap_txids: proposed_swap_txids
                        .into_iter()
                        .map(|x| x.try_into().map_err(|_| eyre::eyre!("Invalid txid length")))
                        .collect::<Result<Vec<[u8; 32]>>>()?,
                    release_txid: match r.get::<Option<Vec<u8>>, _>("release_txid") {
                        Some(txid) => Some(
                            txid.try_into()
                                .map_err(|_| eyre::eyre!("Invalid txid length"))?,
                        ),
                        None => None,
                    },
                    withdraw_txid: match r.get::<Option<Vec<u8>>, _>("withdraw_txid") {
                        Some(txid) => Some(
                            txid.try_into()
                                .map_err(|_| eyre::eyre!("Invalid txid length"))?,
                        ),
                        None => None,
                    },
                }))
            }
            None => Ok(None),
        }
    }
}

pub async fn setup_database(in_memory: bool) -> Result<SqlitePool> {
    let db_url = if in_memory {
        "sqlite::memory:"
    } else {
        "sqlite:otc_swaps.db"
    };

    let pool = SqlitePool::connect(db_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}
