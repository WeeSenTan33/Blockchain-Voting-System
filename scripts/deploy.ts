import { ethers } from "ethers";
import dotenv from "dotenv";
import fs from "fs";
dotenv.config();

async function main() {
  const provider = new ethers.JsonRpcProvider(process.env.INFURA_URL!);
  const wallet = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);

  console.log("🚀 Deploying from:", await wallet.getAddress());

  const artifact = JSON.parse(fs.readFileSync("./artifacts/contracts/Voting.sol/Voting.json", "utf8"));
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, wallet);

  const contract = await factory.deploy();
  await contract.waitForDeployment();

  console.log("✅ Voting contract deployed to:", await contract.getAddress());
}

main().catch(console.error);
