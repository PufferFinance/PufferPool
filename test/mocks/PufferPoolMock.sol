// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { EigenPodProxy } from "puffer/EigenPodProxy.sol";
import { IEigenPodProxy } from "puffer/interface/IEigenPodProxy.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { ERC20PermitUpgradeable } from "openzeppelin-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";

contract PufferPoolMock is IPufferPool, ERC20PermitUpgradeable {
    function initialize() external {
        __ERC20_init("pufETH", "pufETH");
    }

    function depositETH(address recipient) external payable { }

    function burn(uint256 pufETHAmount) external { }

    function calculateETHToPufETHAmount(uint256 amount) external view returns (uint256) { }

    function calculatePufETHtoETHAmount(uint256 pufETHAmount) external view returns (uint256) { }

    function getLockedETHAmount() external view returns (uint256) { }

    function getTreasury() external view returns (address) { }

    function getNewRewardsETHAmount() external view returns (uint256) { }

    function getSafeImplementation() external view returns (address) { }

    function getSafeProxyFactory() external view returns (address) { }

    function getPufferAvsAddress() external view returns (address) { }

    function isAVSEnabled(address avs) external view returns (bool) { }

    function getAVSComission(address avs) external view returns (uint256) { }

    function getMinBondRequirement(address avs) external view returns (uint256) { }

    function getPufETHtoETHExchangeRate() external view returns (uint256) { }

    function withdrawFromProtocol(uint256 pufETHAmount, address podRewardsRecipient, uint256 bondAmount)
        external
        payable
    { }

    function getAvsCommission() external view returns (uint256) { }

    function getConsensusCommission() external view returns (uint256) { }

    function getExecutionCommission() external view returns (uint256) { }

    function getBeaconChainETHStrategyIndex() external view returns (uint256) { }

    function getBeaconChainETHStrategy() external view returns (IStrategy) { }

    function getStrategyManager() external view returns (IStrategyManager) { }

    function createPodAccount(address[] calldata podAccountOwners, uint256 threshold) external returns (Safe) { }

    function createPodAccountAndRegisterValidatorKey(
        address[] calldata podAccountOwners,
        uint256 podAccountThreshold,
        ValidatorKeyData calldata data,
        address podRewardsRecipient
    ) external payable returns (Safe, IEigenPodProxy) { }

    function registerValidatorKey(address podAccount, address podRewardsRecipient, ValidatorKeyData calldata data)
        external
        payable
        returns (IEigenPodProxy)
    { }

    function createGuardianAccount(address[] calldata guardiansWallets, uint256 threshold)
        external
        returns (Safe account)
    { }

    function getEigenPodProxyAndEigenPod(bytes calldata blsPubKey) external view returns (address, address) { }

    function getExecutionAmount(uint256 amount) external view returns (uint256) { }

    function provisionPodETH(
        address eigenPodProxy,
        bytes calldata pubkey,
        bytes calldata signature,
        bytes[] calldata guardianEnclaveSignatures,
        bytes32 depositDataRoot
    ) external { }

    function updateETHBackingAmount(uint256 amount) external { }
}
