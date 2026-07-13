// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CyberShieldRegistry {
    struct ScamRecord {
        bytes32 evidenceHash;
        string category;
        string details;
        string target;
        address reporter;
        uint256 timestamp;
    }

    ScamRecord[] public records;
    mapping(bytes32 => bool) public isLogged;

    event ScamLogged(
        bytes32 indexed evidenceHash,
        string category,
        string target,
        address indexed reporter,
        uint256 timestamp
    );

    function logScam(
        string memory _category,
        string memory _details,
        string memory _target
    ) public returns (bytes32) {
        // Generate unique hash for this logging event
        bytes32 hash = keccak256(abi.encodePacked(_category, _details, _target, block.timestamp, msg.sender));
        
        ScamRecord memory newRecord = ScamRecord({
            evidenceHash: hash,
            category: _category,
            details: _details,
            target: _target,
            reporter: msg.sender,
            timestamp: block.timestamp
        });

        records.push(newRecord);
        isLogged[hash] = true;

        emit ScamLogged(hash, _category, _target, msg.sender, block.timestamp);
        return hash;
    }

    function getRecordCount() public view returns (uint256) {
        return records.length;
    }

    function getRecord(uint256 index) public view returns (
        bytes32 evidenceHash,
        string memory category,
        string memory details,
        string memory target,
        address reporter,
        uint256 timestamp
    ) {
        require(index < records.length, "Index out of bounds");
        ScamRecord memory r = records[index];
        return (
            r.evidenceHash,
            r.category,
            r.details,
            r.target,
            r.reporter,
            r.timestamp
        );
    }
}
