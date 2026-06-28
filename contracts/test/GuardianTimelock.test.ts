import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { GuardianTimelock } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("GuardianTimelock", function () {
  let timelock: GuardianTimelock;
  let deployer: SignerWithAddress, proposer: SignerWithAddress, executor: SignerWithAddress, other: SignerWithAddress;
  const MIN_DELAY = 24 * 60 * 60; // 24 hours in seconds

  beforeEach(async function () {
    [deployer, proposer, executor, other] = await ethers.getSigners();

    const GuardianTimelock = await ethers.getContractFactory(
      "GuardianTimelock"
    );
    timelock = (await GuardianTimelock.deploy(
      [proposer.address],        // proposers
      [ethers.ZeroAddress],      // open execution
      deployer.address           // admin
    )) as GuardianTimelock;
    await timelock.waitForDeployment();
  });

  describe("Deployment", function () {
    it("should set correct minimum delay", async function () {
      expect(await timelock.getMinDelay()).to.equal(MIN_DELAY);
    });

    it("should set MIN_DELAY constant to 24 hours", async function () {
      expect(await timelock.MIN_DELAY()).to.equal(MIN_DELAY);
    });

    it("should grant proposer role to proposer address", async function () {
      const PROPOSER_ROLE = await timelock.PROPOSER_ROLE();
      expect(
        await timelock.hasRole(PROPOSER_ROLE, proposer.address)
      ).to.be.true;
    });

    it("should grant executor role to zero address (open)", async function () {
      const EXECUTOR_ROLE = await timelock.EXECUTOR_ROLE();
      expect(
        await timelock.hasRole(EXECUTOR_ROLE, ethers.ZeroAddress)
      ).to.be.true;
    });
  });

  describe("Delay enforcement", function () {
    it("should not allow execution before delay has passed", async function () {
      const target = await timelock.getAddress();
      const value = 0;
      const data = "0x";
      const predecessor = ethers.ZeroHash;
      const salt = ethers.id("test-salt-1");

      // Schedule operation
      await timelock.connect(proposer).schedule(
        target, value, data, predecessor, salt, MIN_DELAY
      );

      // Try to execute immediately — should fail
      await expect(
        timelock.execute(target, value, data, predecessor, salt)
      ).to.be.revertedWithCustomError(
        timelock, "TimelockUnexpectedOperationState"
      );
    });

    it("should allow execution after delay has passed", async function () {
      const target = await timelock.getAddress();
      const value = 0;
      const data = "0x";
      const predecessor = ethers.ZeroHash;
      const salt = ethers.id("test-salt-2");

      await timelock.connect(proposer).schedule(
        target, value, data, predecessor, salt, MIN_DELAY
      );

      // Fast forward 24 hours + 1 second
      await time.increase(MIN_DELAY + 1);

      // Should not revert (no-op call to self)
      await expect(
        timelock.execute(target, value, data, predecessor, salt)
      ).to.not.be.reverted;
    });
  });

  describe("Cancellation", function () {
    it("should allow proposer to cancel a scheduled operation", async function () {
      const target = await timelock.getAddress();
      const value = 0;
      const data = "0x";
      const predecessor = ethers.ZeroHash;
      const salt = ethers.id("test-salt-3");

      await timelock.connect(proposer).schedule(
        target, value, data, predecessor, salt, MIN_DELAY
      );

      const id = await timelock.hashOperation(
        target, value, data, predecessor, salt
      );

      await timelock.connect(proposer).cancel(id);

      expect(
        await timelock.isOperation(id)
      ).to.be.false;
    });
  });
});
