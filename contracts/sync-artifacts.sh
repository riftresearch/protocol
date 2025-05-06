#!/bin/bash

# Helper script to compile contract artifacts and move them to artifacts/ dir 

# Compile contracts
(forge build)

# Clean and create artifacts directory
mkdir -p artifacts
rm -rf artifacts/*

# Copy compiled artifacts
# cp out/RiftExchange.sol/RiftExchange.json artifacts/
cp out/SyntheticBTC.t.sol/SyntheticBTC.json artifacts/
cp out/SP1MockVerifier.sol/SP1MockVerifier.json artifacts/
cp out/BTCDutchAuctionHouse.sol/BTCDutchAuctionHouse.json artifacts/
cp out/HelperTypes.t.sol/HelperTypes.json artifacts/
cp out/RiftTest.t.sol/RiftExchangeHarness.json artifacts/