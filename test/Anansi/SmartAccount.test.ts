import { Wallet } from "ethers";
import { ethers } from "hardhat";
import { expect } from "chai";
import {
  ERC1967Proxy__factory,
  EntryPoint,
  SimpleAccount,
  SimpleAccountFactory__factory,
  SimpleAccount__factory,
  SmartAccountFactory,
  SmartAccountFactory__factory,
  TestCounter,
  TestCounter__factory,
  TestUtil,
  TestUtil__factory,
} from "../../typechain";
import {
  getBalance,
  isDeployed,
  ONE_ETH,
  HashZero,
  deployEntryPoint,
  createAccount,
} from "../testutils";
import {
  fillUserOpDefaults,
  getUserOpHash,
  encodeUserOp,
  signUserOp,
  packUserOp,
} from "../UserOp";
import { parseEther } from "ethers/lib/utils";
import { UserOperation } from "../UserOperation";

describe("Smart Account Tests", () => {
  const ens1 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Max"));
  const ens2 = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Maxyz"));
  let entryPoint: EntryPoint;
  let entryPointAddress: string;
  let accounts: string[];
  let accountFactory: SmartAccountFactory;
  const ethersSigner = ethers.provider.getSigner();

  before("Deploy contracts", async function () {
    accounts = await ethers.provider.listAccounts();

    entryPoint = await deployEntryPoint();
    entryPointAddress = entryPoint.address;

    accountFactory = await new SmartAccountFactory__factory(
      ethersSigner
    ).deploy(entryPointAddress);
  });
  it("owner should be able to call transfer", async () => {
    const tx = await accountFactory.createAccount(accounts[1], ens1);
    const receipt = await tx.wait(1);
    console.log(receipt);
    const accountAddress = await accountFactory.getAddress(ens1);
    console.log(accountAddress);
  });

  it("reverts to create a new account with same name and another owner", async () => {
    const tx = await accountFactory.createAccount(accounts[2], ens1);
    const receipt = await tx.wait(1);
    console.log(receipt);
    const accountAddress = await accountFactory.getAddress(ens1);
    console.log(accountAddress);
  });
});
