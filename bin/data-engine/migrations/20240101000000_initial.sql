CREATE TABLE IF NOT EXISTS otc_swaps (
    id                  BLOB(32)     NOT NULL PRIMARY KEY, -- 32-byte primary key
    depositor           BLOB(20)     NOT NULL,             -- 20 bytes for an EVM address
    recipient           BLOB(20)     NOT NULL,             
    deposit_vault       TEXT         NOT NULL,  -- JSON encoded DepositVault
    deposit_txid        BLOB(32)     NOT NULL,
    deposit_block_number BIGINT      NOT NULL,
    deposit_block_hash  BLOB(32)     NOT NULL,
    proposed_swaps      TEXT         NOT NULL,  -- JSON array of ProposedSwap
    proposed_swap_txids TEXT         NOT NULL,  -- JSON array of 32-byte TXIDs
    release_txid        BLOB(32),
    withdraw_txid       BLOB(32)
);
