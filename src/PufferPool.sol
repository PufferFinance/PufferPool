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
import { ECDSA } from "openzeppelin/utils/cryptography/ECDSA.sol";
import { FixedPointMathLib } from "solady/utils/FixedPointMathLib.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { EnumerableSet } from "openzeppelin/utils/structs/EnumerableSet.sol";
import { IEnclaveVerifier } from "puffer/EnclaveVerifier.sol";
import { RaveEvidence } from "puffer/interface/RaveEvidence.sol";

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
    ERC20PermitUpgradeable
{
    using SafeTransferLib for address;
    using ECDSA for bytes32;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /**
     * @dev EigenLayer's Strategy Manager
     */
    IStrategyManager public immutable STRATEGY_MANAGER;

    /**
     * @dev Guaridans
     */
    address public immutable GUARDIANS;

    /**
     * @dev ETH Amount required for becoming a Validator
     */
    uint256 internal constant _32_ETHER = 32 ether;

    /**
     * @dev BLS public keys are 48 bytes long
     */
    uint256 internal constant _BLS_PUB_KEY_LENGTH = 48;

    /**
     * @dev Constant representing 100%
     */
    uint256 internal constant _ONE_HUNDRED_WAD = 100 * 1e18; // 1e18 = WAD

    /**
     * @dev Minimum deposit amount in ETH
     */
    uint256 internal constant _MINIMUM_DEPOSIT_AMOUNT = 0.01 ether;

    /**
     * @dev Locked ETH amount
     */
    uint256 internal _lockedETHAmount;

    /**
     * @dev New rewards amount
     */
    uint256 internal _newETHRewardsAmount;

    /**
     * @dev Guardians multisig wallet
     */
    Safe internal _guardiansMultisig;

    /**
     * @dev EigenPodProxy -> EigenPodProxyInformation
     * eigenPodProxy -> info
     */
    mapping(address => EigenPodProxyInformation) internal _eigenPodProxies;

    /**
     * @dev Actively validated services (AVSs) configuration
     * AVS -> parameters
     */
    mapping(address => AVSParams) internal _allowedAVSs;

    /**
     * @dev Address of the Puffer AVS contract
     */
    // TODO:
    // address internal _pufferAvsAddress;

    /**
     * @dev Number of shares out of one billion to split AVS rewards with the pool
     */
    uint256 internal _avsCommission;

    /**
     * @dev Number of shares out of one billion to split consensus rewards with the pool
     */
    uint256 internal _consensusCommission;

    /**
     * @dev Number of shares out of one billion to split execution rewards with the pool
     */
    uint256 internal _executionCommission;

    /**
     * @dev Protocol fee rate, can be updated by governance (1e20 = 100%, 1e18 = 1%)
     */
    uint256 internal _protocolFeeRate;

    /**
     * @dev Puffer finance treasury
     */
    address payable public immutable TREASURY;

    /**
     * @dev Validator bond for non custodial node runners
     */
    uint256 internal _nonCustodialBondRequirement;

    /**
     * @dev Validator bond for non enclave node runners
     */
    uint256 internal _nonEnclaveBondRequirement;

    /**
     * @dev Validator bond for Enclave node runners
     */
    uint256 internal _enclaveBondRequirement;

    /**
     * @dev Withdrawal pool address
     */
    address internal _withdrawalPool;

    /**
     * @dev Guardian {Safe} Module
     */
    GuardianModule internal _guardianModule;

    /**
     * @dev Enclave verifier smart contract
     */
    IEnclaveVerifier internal _enclaveVerifier;

    bytes32 internal _mrenclave;
    bytes32 internal _mrsigner;
    bytes32 internal _guardianMrenclave;
    bytes32 internal _guardianMrsigner;

    /**
     * @dev Public keys of the active validators
     */
    EnumerableSet.Bytes32Set internal _pubKeyHashes;

    /**
     * @dev Allow a call from guardians multisig
     */
    modifier onlyGuardians() {
        _onlyGuardians();
        _;
    }

    modifier onlyPodProxy() {
        // Ensure caller corresponds to an instantiated PodPoxy contract
        if (_eigenPodProxies[msg.sender].creator == address(0)) {
            revert Unauthorized();
        }
        _;
    }

    constructor(address payable treasury, address guardians) {
        TREASURY = treasury;
        emit TreasuryChanged(address(0), treasury);

        GUARDIANS = guardians;

        STRATEGY_MANAGER = IStrategyManager(address(1234)); // TODO
        _disableInitializers();
    }

    /**
     * @notice no calldata automatically triggers the depositETH for `msg.sender`
     */
    receive() external payable {
        depositETH(msg.sender);
    }

    // slither-disable-next-line missing-zero-check
    function initialize(
        address withdrawalPool,
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
    }

    // Guardians only

    function updateETHBackingAmount(uint256 amount) external onlyGuardians { }

    /**
     * @inheritdoc IPufferPool
     */
    function provisionPodETH(
        address eigenPodProxy,
        bytes calldata pubKey,
        bytes calldata signature,
        bytes32 depositDataRoot,
        bytes[] calldata guardianEnclaveSignatures
    ) external {
        bytes32 pubKeyHash = keccak256(pubKey);

        // Make sure that the validator is in the correct status
        if (
            _eigenPodProxies[address(eigenPodProxy)].validatorInformation[pubKeyHash].status
                != IPufferPool.Status.PENDING
        ) {
            revert InvalidBLSPubKey();
        }

        // Validate guardian signatures
        _validateGuardianSignatures({
            eigenPodProxy: eigenPodProxy,
            pubKey: pubKey,
            guardianEnclaveSignatures: guardianEnclaveSignatures,
            signature: signature,
            depositDataRoot: depositDataRoot
        });

        // Update Validator status
        _eigenPodProxies[eigenPodProxy].validatorInformation[pubKeyHash].status = IPufferPool.Status.VALIDATING;

        // Update locked ETH Amount
        _lockedETHAmount += _32_ETHER;

        // @audit-ok no reentrancy because EigenPodProxy is our own contract that forwards ETH
        // to EigenPod, and EigenPod forwards to ETH Staking contract
        // slither-disable-next-line arbitrary-send-eth
        // beaconchain,.stake.callStake{ value: _32_ETHER }({
        //     pubKey: pubKey,
        //     signature: signature,
        //     depositDataRoot: depositDataRoot
        // });

        emit ETHProvisioned(eigenPodProxy, pubKey, block.timestamp);
    }

    function _getMessageToBeSigned(
        address eigenPodProxy,
        bytes calldata pubKey,
        bytes calldata signature,
        bytes32 depositDataRoot
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(pubKey, _withdrawalPool, signature, depositDataRoot, _expectCustody(eigenPodProxy, pubKey))
        ).toEthSignedMessageHash();
    }

    /**
     * @inheritdoc IPufferPool
     */
    function depositETH(address recipient) public payable whenNotPaused returns (uint256) {
        if (msg.value < _MINIMUM_DEPOSIT_AMOUNT) {
            revert InsufficientETH();
        }

        uint256 pufETHAmount = _calculateETHToPufETHAmount(msg.value);

        _mint(recipient, pufETHAmount);

        emit Deposited(msg.sender, recipient, msg.value, pufETHAmount);

        return pufETHAmount;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function burn(uint256 pufETHAmount) external whenNotPaused {
        _burn(msg.sender, pufETHAmount);
    }

    function registerValidatorKey(ValidatorKeyData calldata data) public payable whenNotPaused {
        // Sanity check on blsPubKey
        if (data.blsPubKey.length != _BLS_PUB_KEY_LENGTH) {
            revert InvalidBLSPubKey();
        }

        bytes32 pubKeyHash = keccak256(data.blsPubKey);

        // Make sure that there are no duplicate keys
        bool added = _pubKeyHashes.add(pubKeyHash);
        if (!added) {
            revert PublicKeyIsAlreadyActive();
        }

        // Determine bond requirement from inputs
        uint256 validatorBondRequirement =
            _getValidatorBondRequirement(data.evidence.report.length, data.blsEncryptedPrivKeyShares.length);
        if (msg.value != validatorBondRequirement) {
            revert InvalidAmount();
        }

        // Verify enclave remote attestation evidence
        if (validatorBondRequirement != _nonCustodialBondRequirement) {
            bytes32 raveCommitment = _buildNodeRaveCommitment(data, _withdrawalPool);
            _verifyKeyRequirements(data, raveCommitment);
        }

        // Mint pufETH to validator and lock it there
        uint256 pufETHBondAmount = _calculateETHToPufETHAmount(msg.value);
        _mint(address(1234), pufETHBondAmount);

        // Save information
        _eigenPodProxies[address(1234)].validatorInformation[pubKeyHash] =
            IPufferPool.ValidatorInfo({ bond: pufETHBondAmount, status: IPufferPool.Status.PENDING });

        emit ValidatorKeyRegistered(address(1234), data.blsPubKey);
    }

    /**
     * @inheritdoc IPufferPool
     */
    function stopRegistration(bytes32 publicKeyHash) external {
        // `msg.sender` is EigenPodProxy
        IPufferPool.ValidatorInfo storage info = _eigenPodProxies[msg.sender].validatorInformation[publicKeyHash];

        if (info.status != IPufferPool.Status.PENDING) {
            revert InvalidValidatorStatus();
        }

        uint256 bond = info.bond;
        // Remove Bond amount and update status
        info.bond = 0;
        info.status = IPufferPool.Status.BOND_WITHDRAWN;

        // Trigger the pufETH transfer
        // IEigenPodProxy(msg.sender).releaseBond(bond);
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
    function setNodeEnclaveMeasurements(bytes32 mrenclave, bytes32 mrsigner) external onlyOwner {
        bytes32 oldMrenclave = _mrenclave;
        bytes32 oldMrsigner = _mrsigner;
        _mrenclave = mrenclave;
        _mrsigner = mrsigner;
        emit NodeEnclaveMeasurementsChanged(oldMrenclave, mrenclave, oldMrsigner, mrsigner);
    }

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
    function getValidatorInfo(address eigenPodProxy, bytes32 pubKeyHash) external view returns (ValidatorInfo memory) {
        return _eigenPodProxies[eigenPodProxy].validatorInformation[pubKeyHash];
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
    function getExecutionCommission() external view returns (uint256) {
        return _executionCommission;
    }

    /**
     * @inheritdoc IPufferPool
     */
    function getNodeEnclaveMeasurements() public view returns (bytes32, bytes32) {
        return (_mrenclave, _mrsigner);
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
                + (address(this).balance - ethDepositedAmount),
            pufETHSupply
        );

        return exchangeRate;
    }

    // TODO: timelock on upgrade?
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner { }

    function _buildNodeRaveCommitment(ValidatorKeyData calldata data, address withdrawalCredentials)
        public
        view
        returns (bytes32)
    {
        ValidatorRaveData memory raveData = ValidatorRaveData({
            pubKey: data.blsPubKey,
            signature: data.signature,
            depositDataRoot: data.depositDataRoot,
            blsEncryptedPrivKeyShares: data.blsEncryptedPrivKeyShares,
            blsPubKeyShares: data.blsPubKeyShares
        });

        return keccak256(
            abi.encode(
                raveData,
                withdrawalCredentials,
                _guardianModule.getGuardiansEnclaveAddresses(_guardiansMultisig),
                _guardiansMultisig.getThreshold()
            )
        );
    }

    // checks that enough encrypted private keyshares + public keyshares were supplied for each guardian to receive one. Also verify that the raveEvidence is valid and contained the expected and fresh raveCommitment.
    function _verifyKeyRequirements(ValidatorKeyData calldata data, bytes32 raveCommitment) internal view {
        // Validate enough keyshares supplied for all guardians
        uint256 numGuardians = _guardiansMultisig.getOwners().length;
        if (data.blsEncryptedPrivKeyShares.length != numGuardians) {
            revert InvalidBLSPrivateKeyShares();
        }

        if (data.blsPubKeyShares.length != numGuardians) {
            revert InvalidBLSPublicKeyShares();
        }

        // Use RAVE to verify remote attestation evidence
        bool custodyVerified = _enclaveVerifier.verifyEvidence({
            blockNumber: data.blockNumber,
            raveCommitment: raveCommitment,
            evidence: data.evidence,
            mrenclave: _mrenclave,
            mrsigner: _mrsigner
        });

        if (!custodyVerified) {
            revert CouldNotVerifyCustody();
        }
    }

    function _validateGuardianSignatures(
        address eigenPodProxy,
        bytes calldata pubKey,
        bytes calldata signature,
        bytes32 depositDataRoot,
        bytes[] calldata guardianEnclaveSignatures
    ) internal view {
        bytes32 msgToBeSigned = getMessageToBeSigned(eigenPodProxy, pubKey, signature, depositDataRoot);

        address[] memory enclaveAddresses = _guardianModule.getGuardiansEnclaveAddresses(_guardiansMultisig);
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

        if (validSignatures < _guardiansMultisig.getThreshold()) {
            revert Unauthorized();
        }
    }

    function getMessageToBeSigned(
        address eigenPodProxy,
        bytes calldata pubKey,
        bytes calldata signature,
        bytes32 depositDataRoot
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(pubKey, _withdrawalPool, signature, depositDataRoot, _expectCustody(eigenPodProxy, pubKey))
        ).toEthSignedMessageHash();
    }

    function getGuardiansMultisig() external view returns (Safe) {
        return _guardiansMultisig;
    }

    function _expectCustody(address eigenPodProxy, bytes calldata pubKey) internal view returns (bool) {
        return _eigenPodProxies[address(eigenPodProxy)].validatorInformation[keccak256(pubKey)].bond
            != _nonCustodialBondRequirement;
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

    function _onlyGuardians() internal view {
        if (msg.sender != address(_guardiansMultisig)) {
            revert Unauthorized();
        }
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}
