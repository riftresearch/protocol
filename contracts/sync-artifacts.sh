#!/bin/bash

# Helper script to compile contract artifacts and move them to artifacts/ dir 

# Compile contracts
(forge build)

# Clean and create artifacts directory
mkdir -p artifacts
rm -rf artifacts/*

# Copy compiled artifacts
cp out/TokenizedBTC.t.sol/TokenizedBTC.json artifacts/
cp out/SP1MockVerifier.sol/SP1MockVerifier.json artifacts/
cp out/BTCDutchAuctionHouse.sol/BTCDutchAuctionHouse.json artifacts/
cp out/HelperTypes.t.sol/HelperTypes.json artifacts/
cp out/RiftTest.t.sol/RiftExchangeHarness.json artifacts/
cp out/MappingWhitelist.sol/MappingWhitelist.json artifacts/
cp out/BitcoinLightClient.sol/BitcoinLightClient.json artifacts/
cp out/RiftExchange.sol/RiftExchange.json artifacts/
cp out/RiftAuctionAdaptor.sol/RiftAuctionAdaptor.json artifacts/
cp out/Bundler3.sol/Bundler3.json artifacts/
cp out/GeneralAdapter1.sol/GeneralAdapter1.json artifacts/
cp out/ParaswapAdapter.sol/ParaswapAdapter.json artifacts/
cp out/ERC20.sol/ERC20.json artifacts/
cp out/LibExposer.sol/LibExposer.json artifacts/
