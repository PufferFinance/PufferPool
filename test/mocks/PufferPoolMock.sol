// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { ERC20PermitUpgradeable } from "openzeppelin-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { IEnclaveVerifier } from "puffer/EnclaveVerifier.sol";

contract PufferPoolMock is IPufferPool, ERC20PermitUpgradeable {
    function initialize() external {
        __ERC20_init("pufETH", "pufETH");
    }

    address payable public constant TREASURY = payable(address(444));

    receive() external payable {
        // take the money
    }

    function getWithdrawalPool() external view returns (address) { }

    function depositETH() external payable returns (uint256) { }

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

    function getAVSCommission(address avs) external view returns (uint256) { }

    function getMinBondRequirement(address avs) external view returns (uint256) { }

    function getPufETHtoETHExchangeRate() external view returns (uint256) { }

    function withdrawFromProtocol(uint256 pufETHAmount, address podRewardsRecipient) external payable { }

    function getAvsCommission() external view returns (uint256) { }

    function getConsensusCommission() external view returns (uint256) {
        return (10 * FixedPointMathLib.WAD); // 10%
    }

    function getExecutionCommission() external pure returns (uint256) {
        return (5 * FixedPointMathLib.WAD); // 5%
    }

    function getBeaconChainETHStrategyIndex() external view returns (uint256) { }

    function getValidatorWithdrawalCredentials(address eigenPodProxy) external view returns (bytes32) { }

    function getBeaconChainETHStrategy() external view returns (IStrategy) { }

    function STRATEGY_MANAGER() external view returns (IStrategyManager) { }

    function getProtocolFeeRate() external view returns (uint256) { }

    function createGuardianAccount(address[] calldata guardiansWallets, uint256 threshold, bytes calldata data)
        external
        returns (Safe account)
    { }

    function getEigenPodProxyAndEigenPod(address[] calldata podAccountOwners)
        external
        view
        returns (address, address)
    { }

    function getGuardians() external view returns (Safe) { }

    function getEnclaveVerifier() external view returns (IEnclaveVerifier) { }

    function getConsensusVault() external view returns (address) { }
    function getExecutionRewardsVault() external view returns (address) { }
    function getExecutionAmount(uint256 amount) external view returns (uint256) { }

    function provisionNodeETH(
        bytes calldata signature,
        bytes32 depositDataRoot,
        bytes[] calldata guardianEnclaveSignatures
    ) external { }

    function updateETHBackingAmount(uint256 amount) external { }

    function stopRegistration(uint256 validatorIndex) external { }

    function getValidatorInfo(uint256 pubKey) external view returns (Validator memory) { }

    function getNodeEnclaveMeasurements() external returns (bytes32 mrenclave, bytes32 mrsigner) { }

    function getGuardianEnclaveMeasurements() external returns (bytes32 mrenclave, bytes32 mrsigner) { }
}
