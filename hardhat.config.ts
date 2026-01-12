// hardhat.config.ts
import "@nomicfoundation/hardhat-viem";
import { HardhatUserConfig } from "hardhat/config";
import dotenv from "dotenv";
dotenv.config();

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  
  networks: {
    sepolia: {
      type: "http",   
      url: process.env.INFURA_URL as string,
      accounts: [process.env.PRIVATE_KEY as string],
    },
    localhost: {
      type: "http",   
      url: "http://127.0.0.1:8000",
    },
  },
};

export default config;
