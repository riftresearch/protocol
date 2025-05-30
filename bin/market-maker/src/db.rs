use alloy::primitives::U256;
use eyre::Result;
use rift_core::order_hasher::SolidityHash;
use sol_bindings::Order;
use tokio_rusqlite::Connection;

pub const ORDER_STATUS_SENT: &str = "sent";
pub const ORDER_STATUS_CONFIRMED: &str = "confirmed";
pub const ORDER_STATUS_FAILED: &str = "failed";

pub async fn setup_utxo_database(connection: &Connection) -> Result<()> {
    // Initialize the database table
    connection
        .call(|conn| {
            conn.execute(
                "CREATE TABLE IF NOT EXISTS processed_swaps (
                    deposit_commitment TEXT PRIMARY KEY,
                    txid TEXT NOT NULL,
                    amount_sats INTEGER NOT NULL,
                    timestamp INTEGER NOT NULL
                )",
                [],
            )?;
            Ok::<_, tokio_rusqlite::Error>(())
        })
        .await?;

    Ok(())
}

pub async fn setup_order_filler_database(connection: &Connection) -> Result<()> {
    connection
        .call(|conn| {
            conn.execute(
                "CREATE TABLE IF NOT EXISTS processed_orders (
                    order_index INTEGER PRIMARY KEY,
                    order_hash TEXT NOT NULL,
                    bitcoin_txid TEXT NOT NULL,
                    amount_sats INTEGER NOT NULL,
                    processed_timestamp INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('sent', 'confirmed', 'failed')),
                    retry_count INTEGER DEFAULT 0,
                    last_error TEXT,
                    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
                )",
                [],
            )?;

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_processed_orders_hash ON processed_orders(order_hash)",
                [],
            )?;

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_processed_orders_status ON processed_orders(status)",
                [],
            )?;

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_processed_orders_timestamp ON processed_orders(processed_timestamp)",
                [],
            )?;

            Ok::<_, tokio_rusqlite::Error>(())
        })
        .await?;

    Ok(())
}

pub async fn is_order_already_processed(connection: &Connection, order: &Order) -> Result<bool> {
    let order_hash = hex::encode(order.hash());
    is_order_processed_by_hash(connection, &order_hash).await
}

pub async fn is_order_processed_by_hash(connection: &Connection, order_hash: &str) -> Result<bool> {
    let order_hash = order_hash.to_string();

    let exists = connection
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT EXISTS(SELECT 1 FROM processed_orders WHERE order_hash = ?1 LIMIT 1)",
            )?;
            let exists: bool = stmt.query_row([order_hash], |row| row.get(0))?;
            Ok(exists)
        })
        .await?;

    Ok(exists)
}

pub async fn store_processed_order(
    connection: &Connection,
    order: &Order,
    bitcoin_txid: &str,
    status: &str,
) -> Result<()> {
    let order_index = order.index.to::<u64>() as i64;
    let order_hash = hex::encode(order.hash());
    let amount_sats = order.expectedSats as i64;
    let processed_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let bitcoin_txid = bitcoin_txid.to_string();
    let status = status.to_string();

    connection
        .call(move |conn| {
            conn.execute(
                "INSERT INTO processed_orders (
                    order_index, 
                    order_hash, 
                    bitcoin_txid, 
                    amount_sats, 
                    processed_timestamp, 
                    status
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                [
                    order_index.to_string(),
                    order_hash,
                    bitcoin_txid,
                    amount_sats.to_string(),
                    processed_timestamp.to_string(),
                    status,
                ],
            )?;
            Ok::<_, tokio_rusqlite::Error>(())
        })
        .await?;

    Ok(())
}

pub async fn update_order_status(
    connection: &Connection,
    order_hash: &str,
    new_status: &str,
    error_message: Option<&str>,
) -> Result<()> {
    let order_hash = order_hash.to_string();
    let new_status = new_status.to_string();
    let error_message = error_message.map(|s| s.to_string());

    connection
        .call(move |conn| {
            if let Some(error) = error_message {
                conn.execute(
                    "UPDATE processed_orders 
                     SET status = ?1, last_error = ?2, retry_count = retry_count + 1 
                     WHERE order_hash = ?3",
                    [new_status, error, order_hash],
                )?;
            } else {
                conn.execute(
                    "UPDATE processed_orders 
                     SET status = ?1, last_error = NULL 
                     WHERE order_hash = ?2",
                    [new_status, order_hash],
                )?;
            }
            Ok::<_, tokio_rusqlite::Error>(())
        })
        .await?;

    Ok(())
}
