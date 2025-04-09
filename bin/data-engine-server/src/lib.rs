use alloy::hex;
use alloy::primitives::Address;
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::Method;
use axum::response::IntoResponse;
use axum::{extract::State, routing::get, Json, Router};
use bitcoin_light_client_core::hasher::Digest;
use bitcoin_light_client_core::leaves::BlockLeaf;
use clap::{command, Parser};
use data_engine::engine::ContractDataEngine;
use data_engine::models::OTCSwap;
use eyre::Result;
use regex::Regex;
use rift_sdk::{create_websocket_provider, DatabaseLocation};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::task::JoinSet;
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone, Parser)]
#[command(author, version, about, long_about = None)]
pub struct ServerConfig {
    #[arg(short, long)]
    pub evm_rpc_websocket_url: String,
    #[arg(short, long)]
    pub rift_exchange_address: String,
    #[arg(short, long)]
    pub checkpoint_file: String,
    #[arg(short, long)]
    pub deploy_block_number: u64,
    #[arg(short, long)]
    pub port: u16,
    #[arg(short, long)]
    pub database_location: DatabaseLocation,
}

/// DataEngineServer holds the underlying data engine, starting the Axum server in the background.
/// It provides a getter method for easy access to the inner engine.
pub struct DataEngineServer {
    data_engine: Arc<ContractDataEngine>,
}

impl DataEngineServer {
    /// Spawns an Axum server that serves the API endpoints.
    ///
    /// This helper method abstracts the common server startup logic.
    fn spawn_server(
        data_engine: Arc<ContractDataEngine>,
        port: u16,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Result<()> {
        // Build the Axum application.
        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE])
            .allow_origin(allow_rift_exchange_and_localhost())
            .allow_credentials(true)
            .expose_headers([CONTENT_TYPE, CONTENT_LENGTH])
            .max_age(std::time::Duration::from_secs(3600));

        let app = Router::new()
            .route("/swaps", get(get_swaps_for_address))
            .route("/tip-proof", get(get_tip_proof))
            .route("/contract-bitcoin-tip", get(get_latest_contract_block))
            .route("/health", get(health))
            .layer(cors)
            .with_state(data_engine.clone());

        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        tracing::info!("Listening on {}", addr);

        // Spawn the server in a non-blocking fashion.
        join_set.spawn(async move {
            if let Err(e) =
                axum::serve(tokio::net::TcpListener::bind(&addr).await.unwrap(), app).await
            {
                tracing::error!("Server error: {:?}", e);
            }
            Ok(())
        });
        Ok(())
    }

    /// Asynchronously creates a new DataEngineServer.
    ///
    /// This method sets up the data engine. If needed, it seeds
    /// the underlying MMR with the initial block leaves.
    /// It then starts the HTTP server on the specified port in a background task.
    pub async fn start(
        config: ServerConfig,
        checkpoint_leaves: Vec<BlockLeaf>,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Result<Self> {
        // Create provider and initialize the data engine.
        let provider = create_websocket_provider(&config.evm_rpc_websocket_url).await?;
        let rift_exchange_address = Address::from_str(&config.rift_exchange_address)?;
        let data_engine = Arc::new(
            ContractDataEngine::start(
                &config.database_location,
                Arc::new(provider),
                rift_exchange_address,
                config.deploy_block_number,
                checkpoint_leaves,
                join_set,
            )
            .await?,
        );

        Self::spawn_server(data_engine.clone(), config.port, join_set)?;
        Ok(Self { data_engine })
    }

    /// Creates a new DataEngineServer from an existing Arc<DataEngine> and the provided port.
    ///
    /// This variant accepts a pre-configured DataEngine and immediately starts
    /// the HTTP server on the specified port in a background task.
    pub async fn from_engine(
        data_engine: Arc<ContractDataEngine>,
        port: u16,
        join_set: &mut JoinSet<eyre::Result<()>>,
    ) -> Result<Self> {
        Self::spawn_server(data_engine.clone(), port, join_set)?;
        Ok(Self { data_engine })
    }

    /// Returns a clone of the inner `Arc<DataEngine>`.
    pub fn engine(&self) -> Arc<ContractDataEngine> {
        self.data_engine.clone()
    }
}

fn allow_rift_exchange_and_localhost() -> tower_http::cors::AllowOrigin {
    tower_http::cors::AllowOrigin::predicate(|origin, _| {
        let allowed_domains = vec![
            "http://localhost:3000",
            "http://localhost:8000",
            "https://app.rift.exchange",
        ];
        let regex = Regex::new(r"^https://.*\.rift\.exchange$").unwrap();
        let origin_str = origin.to_str().unwrap_or("");
        allowed_domains.contains(&origin_str) || regex.is_match(origin_str)
    })
}

#[derive(Deserialize, Serialize)]
struct VirtualSwapQuery {
    address: Address,
    page: u32,
}

#[axum::debug_handler]
async fn get_swaps_for_address(
    State(data_engine): State<Arc<ContractDataEngine>>,
    axum::extract::Query(query): axum::extract::Query<VirtualSwapQuery>,
) -> Result<Json<Vec<OTCSwap>>, (axum::http::StatusCode, String)> {
    let swaps = data_engine
        .get_virtual_swaps(query.address, query.page, None)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                format!("Failed to get swaps: {:?}", e),
            )
        })?;
    Ok(Json(swaps))
}

#[derive(Deserialize, Serialize)]
struct TipProofResponse {
    leaf: BlockLeaf,
    siblings: Vec<Digest>,
    peaks: Vec<Digest>,
}

#[axum::debug_handler]
async fn get_tip_proof(
    State(data_engine): State<Arc<ContractDataEngine>>,
) -> Result<Json<TipProofResponse>, (axum::http::StatusCode, String)> {
    let (leaf, siblings, peaks) = data_engine.get_tip_proof().await.map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            format!("Failed to get tip proof: {}", e),
        )
    })?;
    Ok(Json(TipProofResponse {
        leaf,
        siblings,
        peaks,
    }))
}

#[axum::debug_handler]
async fn get_latest_contract_block(
    State(data_engine): State<Arc<ContractDataEngine>>,
) -> Result<Json<u64>, (axum::http::StatusCode, String)> {
    let block_number = data_engine
        .get_leaf_count()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(block_number as u64))
}

#[axum::debug_handler]
async fn health() -> Result<Json<String>, (axum::http::StatusCode, String)> {
    Ok(Json("OK".to_string()))
}
