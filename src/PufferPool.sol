// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { ERC20PermitUpgradeable } from "openzeppelin-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import { ReentrancyGuardUpgradeable } from "openzeppelin-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import { UUPSUpgradeable } from "openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { OwnableUpgradeable } from "openzeppelin-upgradeable/access/OwnableUpgradeable.sol";
import { PausableUpgradeable } from "openzeppelin-upgradeable/security/PausableUpgradeable.sol";
import { GuardianModule } from "puffer/GuardianModule.sol";
import { Safe } from "safe-contracts/Safe.sol";
import { IPufferPool } from "puffer/interface/IPufferPool.sol";
import { IPufferOwner } from "puffer/interface/IPufferOwner.sol";
import { IStrategy } from "eigenlayer/interfaces/IStrategy.sol";
import { IStrategyManager } from "eigenlayer/interfaces/IStrategyManager.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { EnumerableSet } from "openzeppelin/utils/structs/EnumerableSet.sol";
import { IEnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { RaveEvidence } from "puffer/struct/RaveEvidence.sol";
import { IBeaconDepositContract } from "puffer/interface/IBeaconDepositContract.sol";
import { PufferPoolStorage } from "puffer/PufferPoolStorage.sol";
import { AVSParams } from "puffer/struct/AVSParams.sol";
import { Status } from "puffer/struct/Status.sol";
import { Validator } from "puffer/struct/Validator.sol";
import { ValidatorKeyData } from "puffer/struct/ValidatorKeyData.sol";

/**
 * @title PufferPool
 * @author Puffer finance
 * @custom:security-contact security@puffer.fi
 */
contract PufferPool is
    IPufferPool,
    IPufferOwner,
    OwnableUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    ERC20PermitUpgradeable,
    PufferPoolStorage
{
    using SafeTransferLib for address;
    using ECDSA for bytes32;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    IBeaconDepositContract public constant BEACON_DEPOSIT_CONTRACT =
        IBeaconDepositContract(0x00000000219ab540356cBB839Cbe05303d7705Fa);

    /**
     * @dev EigenLayer's Strategy Manager
     */
    IStrategyManager public immutable STRATEGY_MANAGER;

    /**
     * @dev ETH Amount required for becoming a Validator
     */
    uint256 internal constant _32_ETHER = 32 ether;

    /**
     * @dev Constant representing 100%
     */
    uint256 internal constant _ONE_HUNDRED_WAD = 100 * 1e18; // 1e18 = WAD

    /**
     * @dev Minimum deposit amount in ETH
     */
    uint256 internal constant _MINIMUM_DEPOSIT_AMOUNT = 0.01 ether;

    /**
     * @dev Guardians multisig wallet
     */
    Safe public immutable GUARDIANS;

    /**
     * @dev Puffer finance treasury
     */
    address payable public immutable TREASURY;

    /**
     * @dev Allow a call from guardians multisig
     */
    modifier onlyGuardians() {
        _onlyGuardians();
        _;
    }

    constructor(address payable treasury, Safe guardians) payable {
        TREASURY = treasury;
        emit TreasuryChanged(address(0), treasury);

        GUARDIANS = guardians;
        emit GuardiansChanged(address(0), address(guardians));

        STRATEGY_MANAGER = IStrategyManager(address(1234)); // TODO
        _disableInitializers();
    }

    /**
     * @notice no calldata automatically triggers the depositETH for `msg.sender`
     */
    receive() external payable {
        depositETH();
    }

    // slither-disable-next-line missing-zero-check
    function initialize(
        address withdrawalPool,
        address executionRewardsVault,
        address consensusVault,
        address guardianSafeModule,
        address enclaveVerifier,
        bytes calldata emptyData
    ) external initializer {
        __ReentrancyGuard_init(); // TODO: figure out if really need it?
        __UUPSUpgradeable_init();
        __ERC20_init("Puffer ETH", "pufETH");
        __Pausable_init();
        __Ownable_init();
        _setEnclaveVerifier(enclaveVerifier);
        _setNonCustodialBondRequirement(16 ether);
        _setNonEnclaveBondRequirement(8 ether);
        _setEnclaveBondRequirement(2 ether);

        require(emptyData.length == 0);

        _guardianModule = GuardianModule(guardianSafeModule);
        _setProtocolFeeRate(5 * FixedPointMathLib.WAD); // 5%
        _withdrawalPool = withdrawalPool;
        _executionRewardsVault = executionRewardsVault;
        _consensusVault = consensusVault;
    }

    // Guardians only

    function updateETHBackingAmount(uint256 amount) external onlyGuardians { }

    function createValidator(
        bytes calldata pubKey,
        bytes calldata withdrawalCredentials,
        bytes calldata signature,
        bytes32 depositDataRoot
    ) external {
        // TODO: onlyServiceManager modifier

        BEACON_DEPOSIT_CONTRACT.deposit{ value: _32_ETHER }({
            pubkey: pubKey,
            withdrawal_credentials: withdrawalCredentials,
            signature: signature,
            deposit_data_root: depositDataRoot
        });
    }

    // function _getMessageToBeSigned(
    //     address eigenPodProxy,
    //     bytes calldata pubKey,
    //     bytes calldata signature,
    //     bytes32 depositDataRoot
    // ) public view returns (bytes32) {
    //     return keccak256(
    //         abi.encode(pubKey, _withdrawalPool, signature, depositDataRoot, _expectCustody(eigenPodProxy, pubKey))
    //     ).toEthSignedMessageHash();
    // }

    /**
     * @inheritdoc IPufferPool
     */
    function depositETH() public payable whenNotPaused returns (uint256) {
        if (msg.value < _MINIMUM_DEPOSIT_AMOUNT) {
            revert InsufficientETH();
        }

        uint256 pufETHAmount = _calculateETHToPufETHAmount(msg.value);

        emit Deposited(msg.sender, msg.value, pufETHAmount);

        _mint(msg.sender, pufETHAmount);

        return pufETHAmount;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function burn(uint256 pufETHAmount) external whenNotPaused {
        _burn(msg.sender, pufETHAmount);
    }

    function setNewRewardsETHAmount(uint256 amount) external {
        // TODO: everything
        _newETHRewardsAmount = amount;
    }

    // ==== Only Owner ====

    /**
     * @inheritdoc IPufferOwner
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @inheritdoc IPufferOwner
     */
    function resume() external onlyOwner {
        _unpause();
    }

    /**
     * @inheritdoc IPufferOwner
     */
    function changeAVSConfiguration(address avs, AVSParams memory configuration) external onlyOwner {
        _allowedAVSs[avs] = configuration;
        emit AVSConfigurationChanged(avs, configuration);
    }

    // /**
    //  * @inheritdoc IPufferOwner
    //  */
    // function setExecutionCommission(uint256 newValue) external onlyOwner {
    //     _setExecutionCommission(newValue);
    // }

    // /**
    //  * @inheritdoc IPufferOwner
    //  */
    // function setConsensusCommission(uint256 newValue) external onlyOwner {
    //     _setConsensusCommission(newValue);
    // }

    // /**
    //  * @inheritdoc IPufferOwner
    //  */
    // function setAvsCommission(uint256 newValue) external onlyOwner {
    //     _setAvsCommission(newValue);
    // }

    /**
     * @inheritdoc IPufferOwner
     */
    function setGuardianEnclaveMeasurements(bytes32 guardianMrenclave, bytes32 guardianMrsigner) external onlyOwner {
        bytes32 oldMrenclave = _guardianMrenclave;
        bytes32 oldMrsigner = _guardianMrsigner;
        _guardianMrenclave = guardianMrenclave;
        _guardianMrsigner = guardianMrsigner;
        emit GuardianNodeEnclaveMeasurementsChanged(oldMrenclave, guardianMrenclave, oldMrsigner, guardianMrsigner);
    }

    // TODO: do we really need this? use constants?
    function setNonCustodialBondRequirement(uint256 newValue) external onlyOwner {
        _setNonCustodialBondRequirement(newValue);
    }

    function setNonEnclaveBondRequirement(uint256 newValue) external onlyOwner {
        _setNonEnclaveBondRequirement(newValue);
    }

    function setEnclaveBondRequirement(uint256 newValue) external onlyOwner {
        _setEnclaveBondRequirement(newValue);
    }

    /**
     * @inheritdoc IPufferOwner
     */
    function setProtocolFeeRate(uint256 protocolFeeRate) external onlyOwner {
        _setProtocolFeeRate(protocolFeeRate);
    }

    // ==== Only Owner end ====

    function getGuardianModule() external view returns (GuardianModule) {
        return _guardianModule;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function calculateETHToPufETHAmount(uint256 amount) public view returns (uint256) {
        return FixedPointMathLib.divWad(amount, _getPufETHtoETHExchangeRate(0));
    }

    /**
     * @inheritdoc IPufferPool
     */
    function calculatePufETHtoETHAmount(uint256 pufETHAmount) public view returns (uint256) {
        return FixedPointMathLib.mulWad(pufETHAmount, getPufETHtoETHExchangeRate());
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getLockedETHAmount() public view returns (uint256) {
        return _lockedETHAmount;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getNewRewardsETHAmount() public view returns (uint256) {
        return _newETHRewardsAmount;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getWithdrawalPool() external view returns (address) {
        return _withdrawalPool;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getConsensusVault() external view returns (address) {
        return _consensusVault;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getExecutionRewardsVault() external view returns (address) {
        return _executionRewardsVault;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getExecutionCommission() external view returns (uint256) {
        return _executionCommission;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getGuardianEnclaveMeasurements() external view returns (bytes32, bytes32) {
        return (_guardianMrenclave, _guardianMrsigner);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getConsensusCommission() external view returns (uint256) {
        return _consensusCommission;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function isAVSEnabled(address avs) public view returns (bool) {
        return _allowedAVSs[avs].enabled;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getAVSCommission(address avs) public view returns (uint256) {
        return _allowedAVSs[avs].podAVSCommission;
    }

    // TODO: Will remove and replace this with above function
    function getAvsCommission() public view returns (uint256) {
        return _avsCommission;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getMinBondRequirement(address avs) external view returns (uint256) {
        return uint256(_allowedAVSs[avs].minBondRequirement);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getPufETHtoETHExchangeRate() public view returns (uint256) {
        return _getPufETHtoETHExchangeRate(0);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getPufferAvsAddress() external view returns (address) {
        // return _pufferAvsAddress; // TODO:
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getProtocolFeeRate() external view returns (uint256) {
        return _protocolFeeRate;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getEnclaveVerifier() external view returns (IEnclaveVerifier) {
        return _enclaveVerifier;
    }

    function _getPufETHtoETHExchangeRate(uint256 ethDepositedAmount) internal view returns (uint256) {
        uint256 pufETHSupply = totalSupply();
        // slither-disable-next-line incorrect-equality
        if (pufETHSupply == 0) {
            return FixedPointMathLib.WAD;
        }
        // address(this).balance - ethDepositedAmount is actually balance of this contract before the deposit
        uint256 exchangeRate = FixedPointMathLib.divWad(
            getLockedETHAmount() + getNewRewardsETHAmount() + address(_withdrawalPool).balance
                + address(_executionRewardsVault).balance + (address(this).balance - ethDepositedAmount),
            pufETHSupply
        );

        return exchangeRate;
    }

    // TODO: timelock on upgrade?
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner { }

    function _validateGuardianSignatures(
        bytes memory pubKey,
        bytes calldata signature,
        bytes32 depositDataRoot,
        bytes[] calldata guardianEnclaveSignatures
    ) internal view {
        bytes32 msgToBeSigned = getMessageToBeSigned(pubKey, signature, depositDataRoot);

        address[] memory enclaveAddresses = _guardianModule.getGuardiansEnclaveAddresses(GUARDIANS);
        uint256 validSignatures = 0;

        // Iterate through guardian enclave addresses and make sure that the signers match
        for (uint256 i = 0; i < enclaveAddresses.length;) {
            address currentSigner = ECDSA.recover(msgToBeSigned, guardianEnclaveSignatures[i]);
            if (currentSigner == address(0)) {
                revert Unauthorized();
            }
            if (currentSigner == enclaveAddresses[i]) {
                validSignatures++;
            }
            unchecked {
                ++i;
            }
        }

        if (validSignatures < GUARDIANS.getThreshold()) {
            revert Unauthorized();
        }
    }

    function getMessageToBeSigned(bytes memory pubKey, bytes calldata signature, bytes32 depositDataRoot)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(pubKey, _withdrawalPool, signature, depositDataRoot, _expectCustody(pubKey)))
            .toEthSignedMessageHash();
    }

    function _expectCustody(bytes memory pubKey) internal view returns (bool) {
        // return _eigenPodProxies[address(eigenPodProxy)].validatorInformation[keccak256(pubKey)].bond
        //     != _nonCustodialBondRequirement;

        return true;
    }

    function _setEnclaveVerifier(address enclaveVerifier) internal {
        _enclaveVerifier = IEnclaveVerifier(enclaveVerifier);
        emit EnclaveVerifierChanged(enclaveVerifier);
    }

    function _setExecutionCommission(uint256 newValue) internal {
        uint256 oldValue = _executionCommission;
        _executionCommission = newValue;
        emit ExecutionCommissionChanged(oldValue, newValue);
    }

    function _setConsensusCommission(uint256 newValue) internal {
        uint256 oldValue = _consensusCommission;
        _consensusCommission = newValue;
        emit ConsensusCommissionChanged(oldValue, newValue);
    }

    function _setAvsCommission(uint256 newValue) internal {
        uint256 oldValue = _avsCommission;
        _avsCommission = newValue;
        emit AvsCommissionChanged(oldValue, newValue);
    }

    function _setNonCustodialBondRequirement(uint256 newValue) internal {
        uint256 oldValue = _avsCommission;
        _nonCustodialBondRequirement = newValue;
        emit NonCustodialBondRequirementChanged(oldValue, newValue);
    }

    function _setNonEnclaveBondRequirement(uint256 newValue) internal {
        uint256 oldValue = _avsCommission;
        _nonEnclaveBondRequirement = newValue;
        emit NonEnclaveBondRequirementChanged(oldValue, newValue);
    }

    function _setEnclaveBondRequirement(uint256 newValue) internal {
        uint256 oldValue = _avsCommission;
        _enclaveBondRequirement = newValue;
        emit EnclaveBondRequirementChanged(oldValue, newValue);
    }

    function _setProtocolFeeRate(uint256 protocolFee) internal {
        uint256 oldProtocolFee = _protocolFeeRate;
        _protocolFeeRate = protocolFee;
        emit ProtocolFeeRateChanged(oldProtocolFee, protocolFee);
    }

    /**
     * @dev Internal function for calculating the ETH to pufETH amount when ETH is being sent in the transaction
     */
    function _calculateETHToPufETHAmount(uint256 amount) public view returns (uint256) {
        return FixedPointMathLib.divWad(amount, _getPufETHtoETHExchangeRate(amount));
    }

    function _getValidatorBondRequirement(uint256 raveEvidenceLen, uint256 blsEncPrivKeySharesLen)
        internal
        view
        returns (uint256)
    {
        if (raveEvidenceLen + blsEncPrivKeySharesLen == 0) {
            return _nonCustodialBondRequirement;
        }

        if (raveEvidenceLen == 0) {
            return _nonEnclaveBondRequirement;
        }

        return _enclaveBondRequirement;
    }

    function _getSalt(address[] calldata podAccountOwners) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(podAccountOwners)));
    }

    function _getWithdrawalCredentials() internal view returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(_withdrawalPool));
    }

    function _onlyGuardians() internal view {
        if (msg.sender != address(GUARDIANS)) {
            revert Unauthorized();
        }
    }
}
