use eyre::Result;
use tokio_rusqlite::Connection;

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
