// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

error NotMarketMaker();
error ServerNameTooLong();
error MarketMakerAlreadyRegistered();
error InvalidRange();

contract MarketMakerRegistry {
    struct MarketMaker {
        string server;
        address owner;
    }

    MarketMaker[] public mms;
    mapping(address => uint256) private mmIndex;

    event MarketMakerAdded(address indexed owner, string server);
    event MarketMakerDeleted(address indexed owner);

    modifier onlyMarketMaker() {
        if (mmIndex[msg.sender] == 0 && (mms.length == 0 || mms[0].owner != msg.sender)) {
            revert NotMarketMaker();
        }
        _;
    }

    function addMarketMaker(string memory server) external {
        if (bytes(server).length >= 253) {
            revert ServerNameTooLong();
        }
        if (mmIndex[msg.sender] != 0 || (mms.length > 0 && mms[0].owner == msg.sender)) {
            revert MarketMakerAlreadyRegistered();
        }

        mms.push(MarketMaker(server, msg.sender));
        mmIndex[msg.sender] = mms.length - 1;
        emit MarketMakerAdded(msg.sender, server);
    }

    function deleteMarketMaker() external onlyMarketMaker {
        uint256 index = mmIndex[msg.sender];
        uint256 lastIndex = mms.length - 1;

        if (index != lastIndex) {
            mms[index] = mms[lastIndex];
            mmIndex[mms[index].owner] = index;
        }

        mms.pop();
        delete mmIndex[msg.sender];
        emit MarketMakerDeleted(msg.sender);
    }

    function fetchMarketMakerSlice(uint256 start, uint256 end) external view returns (MarketMaker[] memory) {
        if (start >= end || end > mms.length) {
            revert InvalidRange();
        }
        uint256 chunkSize = end - start;
        MarketMaker[] memory chunk = new MarketMaker[](chunkSize);
        for (uint256 i = 0; i < chunkSize; i++) {
            chunk[i] = mms[start + i];
        }
        return chunk;
    }

    function getMarketMakersCount() external view returns (uint256) {
        return mms.length;
    }
}
