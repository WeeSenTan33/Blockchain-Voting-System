// voting_abi.js
export default [
  // ABI from your Voting.json (from Hardhat compile output)
  {
    "inputs": [
      { "internalType": "uint256", "name": "_candidateId", "type": "uint256" }
    ],
    "name": "vote",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  // Add the rest of your contract ABI...
];
