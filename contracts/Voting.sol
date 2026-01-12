// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Voting {
    struct Candidate {
        uint id;
        string name;
        uint voteCount;
    }

    address public admin;
    uint public totalVotes;
    mapping(uint => Candidate) public candidates;
    mapping(string => bool) public hasVotedEmail;  // Track with email
    uint public candidateCount;

    constructor() {
        admin = msg.sender;
    }

    function addCandidate(string memory _name) public {
        require(msg.sender == admin, "Only admin can add");
        candidateCount++;
        candidates[candidateCount] = Candidate(candidateCount, _name, 0);
    }

    function voteAsAdmin(string memory voterEmail, uint _id) public {
        require(msg.sender == admin, "Only admin can vote");
        require(!hasVotedEmail[voterEmail], "This email has already voted");
        require(_id > 0 && _id <= candidateCount, "Invalid candidate");

        candidates[_id].voteCount++;
        totalVotes++;
        hasVotedEmail[voterEmail] = true;
    }

    function getVotes(uint _id) public view returns (uint) {
        return candidates[_id].voteCount;
    }
}
