use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, U256};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::Filter;
use async_trait::async_trait;
use eyre::Result;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use log::{debug, error, info, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sol_bindings::ERC20Instance;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::sleep;

#[async_trait]
pub trait TokenizedBTCRedeemer: Send + Sync {
    async fn redeem(&self, amount_sats: u64) -> Result<String>;
    async fn can_redeem(&self, amount_sats: u64) -> Result<bool>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenizedBTCRedeemerConfig {
    pub coinbase_api_key: String,
    pub coinbase_api_secret: String,
    pub market_maker_btc_address: String,
    pub cbbtc_contract_address: Address,
    pub market_maker_address: Address,
    pub minimum_redeem_threshold_sats: u64,
}

impl Default for TokenizedBTCRedeemerConfig {
    fn default() -> Self {
        Self {
            coinbase_api_key: String::new(),
            coinbase_api_secret: String::new(),
            market_maker_btc_address: String::new(),
            cbbtc_contract_address: Address::ZERO,
            market_maker_address: Address::ZERO,
            minimum_redeem_threshold_sats: 1_000_000,
        }
    }
}

#[derive(Debug, Clone)]
pub enum RedemptionTrigger {
    CbBtcReceived {
        amount_sats: u64,
        tx_hash: String,
    },
    OrderSettled {
        cbbtc_amount_sats: u64,
        order_id: String,
    },
    ManualCheck,
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    sub: String,
    iss: String,
    nbf: i64,
    exp: i64,
    uri: String,
}

struct CoinbaseClient {
    http_client: Client,
    api_key: String,
    api_secret: String,
}

impl CoinbaseClient {
    fn new(api_key: String, api_secret: String) -> Result<Self> {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| eyre::eyre!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            http_client,
            api_key,
            api_secret,
        })
    }

    fn build_jwt(&self, uri: &str) -> Result<String> {
        let now = chrono::Utc::now().timestamp();

        let claims = JwtClaims {
            sub: self.api_key.clone(),
            iss: "cdp".to_string(),
            nbf: now,
            exp: now + 120,
            uri: uri.to_string(),
        };

        let header = Header {
            kid: Some(self.api_key.clone()),
            alg: Algorithm::ES256,
            ..Default::default()
        };

        let key = EncodingKey::from_ec_pem(self.api_secret.as_bytes())
            .map_err(|e| eyre::eyre!("Failed to parse private key: {}", e))?;

        encode(&header, &claims, &key).map_err(|e| eyre::eyre!("Failed to encode JWT: {}", e))
    }

    async fn get_btc_account_id(&self) -> Result<String> {
        let uri = "GET api.coinbase.com/v2/accounts";
        let jwt = self.build_jwt(uri)?;

        let response = self
            .http_client
            .get("https://api.coinbase.com/v2/accounts")
            .header("Authorization", format!("Bearer {}", jwt))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let btc_account = response["data"]
            .as_array()
            .ok_or_else(|| eyre::eyre!("Invalid response format"))?
            .iter()
            .find(|account| account["currency"]["code"] == "BTC")
            .ok_or_else(|| eyre::eyre!("No BTC account found"))?;

        Ok(btc_account["id"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("Invalid account ID"))?
            .to_string())
    }

    async fn get_cbbtc_deposit_address(&self, btc_account_id: &str) -> Result<String> {
        let uri = format!(
            "GET api.coinbase.com/v2/accounts/{}/addresses",
            btc_account_id
        );
        let jwt = self.build_jwt(&uri)?;

        let response = self
            .http_client
            .get(format!(
                "https://api.coinbase.com/v2/accounts/{}/addresses",
                btc_account_id
            ))
            .header("Authorization", format!("Bearer {}", jwt))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let eth_address = response["data"]
            .as_array()
            .ok_or_else(|| eyre::eyre!("Invalid response format"))?
            .iter()
            .find(|addr| addr["network"] == "ethereum")
            .ok_or_else(|| eyre::eyre!("No Ethereum address found"))?;

        Ok(eth_address["address"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("Invalid address"))?
            .to_string())
    }

    async fn send_bitcoin(
        &self,
        to_address: &str,
        amount_btc: &str,
        btc_account_id: &str,
    ) -> Result<String> {
        let uri = format!(
            "POST api.coinbase.com/v2/accounts/{}/transactions",
            btc_account_id
        );
        let jwt = self.build_jwt(&uri)?;

        let payload = json!({
            "type": "send",
            "to": to_address,
            "amount": amount_btc,
            "currency": "BTC",
            "network": "bitcoin"
        });

        let response = self
            .http_client
            .post(format!(
                "https://api.coinbase.com/v2/accounts/{}/transactions",
                btc_account_id
            ))
            .header("Authorization", format!("Bearer {}", jwt))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        Ok(response["data"]["id"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("Invalid transaction ID"))?
            .to_string())
    }

    async fn get_bitcoin_balance(&self, btc_account_id: &str) -> Result<u64> {
        let uri = "GET api.coinbase.com/v2/accounts";
        let jwt = self.build_jwt(uri)?;

        let response = self
            .http_client
            .get("https://api.coinbase.com/v2/accounts")
            .header("Authorization", format!("Bearer {}", jwt))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let btc_account = response["data"]
            .as_array()
            .ok_or_else(|| eyre::eyre!("Invalid response format"))?
            .iter()
            .find(|account| account["id"] == btc_account_id)
            .ok_or_else(|| eyre::eyre!("BTC account not found"))?;

        let balance_str = btc_account["balance"]["amount"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("Invalid balance format"))?;

        let balance_btc: f64 = balance_str
            .parse()
            .map_err(|e| eyre::eyre!("Failed to parse balance: {}", e))?;

        Ok((balance_btc * 100_000_000.0) as u64)
    }
}

pub struct CoinbaseCbBtcProcessor {
    coinbase_client: CoinbaseClient,
    evm_provider: DynProvider,
    cbbtc_contract: Arc<ERC20Instance<DynProvider>>,
    config: TokenizedBTCRedeemerConfig,
}

impl CoinbaseCbBtcProcessor {
    pub fn new(config: TokenizedBTCRedeemerConfig, evm_provider: DynProvider) -> Result<Self> {
        let coinbase_client = CoinbaseClient::new(
            config.coinbase_api_key.clone(),
            config.coinbase_api_secret.clone(),
        )?;

        let cbbtc_contract = Arc::new(ERC20Instance::new(
            config.cbbtc_contract_address,
            evm_provider.clone(),
        ));

        Ok(Self {
            coinbase_client,
            evm_provider,
            cbbtc_contract,
            config,
        })
    }

    pub async fn get_cbbtc_balance(&self) -> Result<u64> {
        let balance = self
            .cbbtc_contract
            .balanceOf(self.config.market_maker_address)
            .call()
            .await?;

        Ok(u64::try_from(balance).unwrap_or(0))
    }

    pub async fn get_bitcoin_balance(&self) -> Result<u64> {
        let btc_account_id = self.coinbase_client.get_btc_account_id().await?;
        self.coinbase_client
            .get_bitcoin_balance(&btc_account_id)
            .await
    }

    async fn send_cbbtc_to_coinbase(
        &self,
        coinbase_address: &str,
        amount_sats: u64,
    ) -> Result<String> {
        let to_address = coinbase_address
            .parse::<Address>()
            .map_err(|e| eyre::eyre!("Invalid address: {}", e))?;

        let transfer_call = self
            .cbbtc_contract
            .transfer(to_address, U256::from(amount_sats));

        let tx_request = transfer_call
            .from(self.config.market_maker_address)
            .into_transaction_request()
            .gas_limit(100_000);

        info!("Sending {} sats cbBTC to Coinbase", amount_sats);

        let pending_tx = self.evm_provider.send_transaction(tx_request).await?;

        let receipt = pending_tx.get_receipt().await?;

        if !receipt.status() {
            return Err(eyre::eyre!("cbBTC transfer failed"));
        }

        Ok(format!("{:?}", receipt.transaction_hash))
    }

    async fn wait_for_conversion(&self, amount_sats: u64) -> Result<()> {
        let initial_balance = self.get_bitcoin_balance().await?;
        let expected_balance = initial_balance + amount_sats;

        info!("Waiting for cbBTC to BTC conversion...");

        for _ in 0..20 {
            sleep(Duration::from_secs(30)).await;

            let current_balance = self.get_bitcoin_balance().await?;
            if current_balance >= expected_balance {
                info!("Conversion completed");
                return Ok(());
            }
        }

        Err(eyre::eyre!("Timeout waiting for conversion"))
    }
}

#[async_trait]
impl TokenizedBTCRedeemer for CoinbaseCbBtcProcessor {
    async fn redeem(&self, amount_sats: u64) -> Result<String> {
        info!("Starting cbBTC redemption for {} sats", amount_sats);

        let btc_account_id = self.coinbase_client.get_btc_account_id().await?;
        let coinbase_eth_address = self
            .coinbase_client
            .get_cbbtc_deposit_address(&btc_account_id)
            .await?;

        let tx_hash = self
            .send_cbbtc_to_coinbase(&coinbase_eth_address, amount_sats)
            .await?;

        self.wait_for_conversion(amount_sats).await?;

        let amount_btc = format!("{:.8}", amount_sats as f64 / 100_000_000.0);
        let btc_tx_id = self
            .coinbase_client
            .send_bitcoin(
                &self.config.market_maker_btc_address,
                &amount_btc,
                &btc_account_id,
            )
            .await?;

        info!(
            "Redemption completed: cbBTC converted and BTC sent. ETH tx: {}, BTC tx: {}",
            tx_hash, btc_tx_id
        );
        Ok(btc_tx_id)
    }

    async fn can_redeem(&self, amount_sats: u64) -> Result<bool> {
        if amount_sats < self.config.minimum_redeem_threshold_sats {
            return Ok(false);
        }

        let cbbtc_balance = self.get_cbbtc_balance().await?;
        Ok(cbbtc_balance >= amount_sats)
    }
}

pub struct RedeemerActor {
    config: TokenizedBTCRedeemerConfig,
    processor: Arc<CoinbaseCbBtcProcessor>,
    trigger_rx: mpsc::Receiver<RedemptionTrigger>,
    trigger_tx: mpsc::Sender<RedemptionTrigger>,
}

impl RedeemerActor {
    pub fn new(config: TokenizedBTCRedeemerConfig, evm_provider: DynProvider) -> Result<Self> {
        let processor = Arc::new(CoinbaseCbBtcProcessor::new(config.clone(), evm_provider)?);
        let (trigger_tx, trigger_rx) = mpsc::channel(100);

        Ok(Self {
            config,
            processor,
            trigger_rx,
            trigger_tx,
        })
    }

    pub fn get_trigger_sender(&self) -> mpsc::Sender<RedemptionTrigger> {
        self.trigger_tx.clone()
    }

    pub async fn run(mut self) -> Result<()> {
        info!("Starting RedeemerActor");

        let mut tasks = JoinSet::new();

        self.spawn_event_listeners(&mut tasks)?;

        loop {
            tokio::select! {
                Some(trigger) = self.trigger_rx.recv() => {
                    match trigger {
                        RedemptionTrigger::CbBtcReceived {
                            amount_sats,
                            tx_hash,
                        } => {
                            info!("cbBTC received: {} sats (tx: {})", amount_sats, tx_hash);
                            self.handle_balance_change().await?;
                        }
                        RedemptionTrigger::OrderSettled {
                            cbbtc_amount_sats,
                            order_id,
                        } => {
                            info!(
                                "Order settled: {} sats (order: {})",
                                cbbtc_amount_sats, order_id
                            );
                            self.handle_balance_change().await?;
                        }
                        RedemptionTrigger::ManualCheck => {
                            debug!("Manual check triggered");
                            self.handle_balance_change().await?;
                        }
                    }
                }
                Some(result) = tasks.join_next() => {
                    match result {
                        Ok(Ok(())) => {
                            error!("Event listener task completed unexpectedly");
                        }
                        Ok(Err(e)) => {
                            error!("Event listener task error: {:?}", e);
                        }
                        Err(e) => {
                            error!("Event listener task panicked: {:?}", e);
                        }
                    }
                    warn!("Respawning event listeners after failure");
                    self.spawn_event_listeners(&mut tasks)?;
                }
                else => {
                    info!("RedeemerActor shutting down");
                    break;
                }
            }
        }

        tasks.shutdown().await;
        Ok(())
    }

    fn spawn_event_listeners(&self, tasks: &mut JoinSet<Result<()>>) -> Result<()> {
        let processor = self.processor.clone();
        let trigger_tx = self.trigger_tx.clone();
        let config = self.config.clone();

        tasks.spawn(async move {
            Self::listen_for_cbbtc_transfers(processor.evm_provider.clone(), config, trigger_tx)
                .await
        });

        info!("Event listeners spawned");
        Ok(())
    }

    async fn listen_for_cbbtc_transfers(
        provider: DynProvider,
        config: TokenizedBTCRedeemerConfig,
        trigger_tx: mpsc::Sender<RedemptionTrigger>,
    ) -> Result<()> {
        let cbbtc_contract_address = config.cbbtc_contract_address;
        let market_maker_address = config.market_maker_address;

        info!(
            "Subscribing to cbBTC Transfer events to {}",
            market_maker_address
        );

        let mut block_subscription = provider
            .subscribe_blocks()
            .await
            .map_err(|e| eyre::eyre!("Failed to subscribe to blocks: {}", e))?;

        info!("Successfully subscribed to new blocks");

        loop {
            match block_subscription.recv().await {
                Ok(block) => {
                    let block_number = block.number;

                    debug!("Processing block {} for cbBTC transfers", block_number);

                    let filter = Filter::new()
                        .address(cbbtc_contract_address)
                        .event("Transfer(address,address,uint256)")
                        .from_block(block_number)
                        .to_block(block_number)
                        .topic2(market_maker_address);

                    match provider.get_logs(&filter).await {
                        Ok(logs) => {
                            for log in logs {
                                if log.topics().len() >= 3 {
                                    let data_bytes = log.data().data.as_ref();
                                    if data_bytes.len() >= 32 {
                                        let amount = U256::from_be_slice(data_bytes);
                                        let amount_sats = u64::try_from(amount).unwrap_or(0);

                                        if amount_sats > 0 {
                                            let tx_hash = format!("{:?}", log.transaction_hash);
                                            info!(
                                                "cbBTC Transfer detected: {} sats in block {}",
                                                amount_sats, block_number
                                            );

                                            if let Err(e) = trigger_tx
                                                .send(RedemptionTrigger::CbBtcReceived {
                                                    amount_sats,
                                                    tx_hash,
                                                })
                                                .await
                                            {
                                                error!("Failed to send trigger: {}", e);
                                                return Err(eyre::eyre!("Trigger channel closed"));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to get logs for block {}: {}", block_number, e);
                        }
                    }
                }
                Err(e) => {
                    error!("Error receiving block: {:?}", e);
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn handle_balance_change(&self) -> Result<()> {
        let cbbtc_balance = self.processor.get_cbbtc_balance().await?;
        let btc_balance = self.processor.get_bitcoin_balance().await?;

        debug!(
            "Balances - cbBTC: {} sats, BTC: {} sats",
            cbbtc_balance, btc_balance
        );

        if cbbtc_balance > btc_balance && cbbtc_balance >= self.config.minimum_redeem_threshold_sats
        {
            let amount_to_redeem = cbbtc_balance - btc_balance;

            info!("Triggering redemption: {} sats", amount_to_redeem);
            match self.processor.redeem(amount_to_redeem).await {
                Ok(tx_id) => info!("Redemption successful: {}", tx_id),
                Err(e) => error!("Redemption failed: {:?}", e),
            }
        } else {
            debug!("No redemption needed");
        }

        Ok(())
    }
}

pub fn create_redeemer_actor(
    config: TokenizedBTCRedeemerConfig,
    evm_provider: DynProvider,
) -> Result<RedeemerActor> {
    RedeemerActor::new(config, evm_provider)
}

pub async fn trigger_redemption_on_order_settled(
    trigger_tx: mpsc::Sender<RedemptionTrigger>,
    cbbtc_amount_sats: u64,
    order_id: String,
) -> Result<()> {
    trigger_tx
        .send(RedemptionTrigger::OrderSettled {
            cbbtc_amount_sats,
            order_id,
        })
        .await?;
    Ok(())
}
