// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { AccessManagedUpgradeable } from "openzeppelin-upgradeable/access/manager/AccessManagedUpgradeable.sol";
import { IDelegationManager } from "eigenlayer/interfaces/IDelegationManager.sol";
import { IPufferProtocol } from "puffer/interface/IPufferProtocol.sol";
import { IEigenPod } from "eigenlayer/interfaces/IEigenPod.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { IDelayedWithdrawalRouter } from "eigenlayer/interfaces/IDelayedWithdrawalRouter.sol";
import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { Unauthorized } from "puffer/Errors.sol";
import { Initializable } from "openzeppelin-upgradeable/proxy/utils/Initializable.sol";
import { MerkleProof } from "openzeppelin/utils/cryptography/MerkleProof.sol";
import { LibGuardianMessages } from "puffer/LibGuardianMessages.sol";
import { Address } from "openzeppelin/utils/Address.sol";

/**
 * @dev Mainnet and latest `master` from EigenLayer are not the same
 * To be compatible with `M1 mainnet deployment` we must use this interface and not the one from repository
 */
interface IEigenPodManager {
    function createPod() external;
    function ownerToPod(address) external returns (address);
    function stake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot) external payable;
}

/**
 * @title PufferModule
 * @author Puffer Finance
 * @notice PufferModule
 * @custom:security-contact security@puffer.fi
 */
contract PufferModule is IPufferModule, Initializable, AccessManagedUpgradeable {
    using Address for address;
    using Address for address payable;

    /**
     * @notice Thrown if the rewards are already claimed for a `blockNumber`
     * @dev Signature "0xa9214540"
     */
    error AlreadyClaimed(uint256 blockNumber, address node);

    /**
     * @notice Thrown if guardians try to post root for an invalid block number
     * @dev Signature "0x9f4aafbe"
     */
    error InvalidBlockNumber(uint256 blockNumber);

    /**
     * @notice Thrown if the there is nothing to be claimed for the provided information
     * @dev Signature "0x64ab3466"
     */
    error NothingToClaim(address node);

    /**
     * @notice Emitted when the rewards MerkleRoot `root` for a `blockNumber` is posted
     */
    event RewardsRootPosted(uint256 indexed blockNumber, bytes32 root);

    /**
     * @dev Upgradeable contract from EigenLayer
     */
    IEigenPodManager public immutable EIGEN_POD_MANAGER;

    /**
     * @dev Upgradeable contract from EigenLayer
     */
    IDelayedWithdrawalRouter public immutable EIGEN_WITHDRAWAL_ROUTER;

    /**
     * @dev Upgradeable contract from EigenLayer
     */
    IDelegationManager public immutable EIGEN_DELEGATION_MANAGER;

    /**
     * @dev Upgradeable PufferProtocol
     */
    IPufferProtocol public immutable PUFFER_PROTOCOL;

    error TooSoon();

    // keccak256(abi.encode(uint256(keccak256("PufferModule.storage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _PUFFER_MODULE_BASE_STORAGE =
        0x501caad7d5b9c1542c99d193b659cbf5c57571609bcfc93d65f1e159821d6200;

    /**
     * @custom:storage-location erc7201:PufferModuleStorage.storage
     * @dev +-----------------------------------------------------------+
     *      |                                                           |
     *      | DO NOT CHANGE, REORDER, REMOVE EXISTING STORAGE VARIABLES |
     *      |                                                           |
     *      +-----------------------------------------------------------+
     */
    struct PufferModuleStorage {
        /**
         * @notice Module Name
         */
        bytes32 moduleName;
        /**
         * @notice Owned EigenPod
         */
        IEigenPod eigenPod;
        /**
         * @notice Timestamp of the last claim of no restaking rewards
         */
        uint256 lastClaimTimestamp;
        /**
         * @dev The last block number for when the rewards root was posted
         */
        uint256 lastProofOfRewardsBlockNumber;
        /**
         * @notice Mapping of a blockNumber and the MerkleRoot for that rewards period
         */
        mapping(uint256 blockNumber => bytes32 root) rewardsRoots;
        /**
         * @notice Mapping that stores which validators have claimed the rewards for a certain blockNumber
         */
        mapping(uint256 blockNumber => mapping(address node => bool claimed)) claimedRewards;
    }

    constructor(
        IPufferProtocol protocol,
        address eigenPodManager,
        IDelayedWithdrawalRouter eigenWithdrawalRouter,
        IDelegationManager delegationManager
    ) payable {
        EIGEN_POD_MANAGER = IEigenPodManager(eigenPodManager);
        EIGEN_WITHDRAWAL_ROUTER = eigenWithdrawalRouter;
        EIGEN_DELEGATION_MANAGER = delegationManager;
        PUFFER_PROTOCOL = protocol;
        _disableInitializers();
    }

    function initialize(
        bytes32 moduleName,
        address initialAuthority,
        string calldata metadataURI,
        address delegationApprover
    ) external initializer {
        __AccessManaged_init(initialAuthority);
        PufferModuleStorage storage $ = _getPufferProtocolStorage();
        $.moduleName = moduleName;
        IEigenPodManager(EIGEN_POD_MANAGER).createPod();
        $.eigenPod = IEigenPod(address(EIGEN_POD_MANAGER.ownerToPod(address(this))));
        //@todo
        // _registerAsOperator(metadataURI, delegationApprover);
    }

    receive() external payable { }

    /**
     * @inheritdoc IPufferModule
     */
    function callStake(bytes calldata pubKey, bytes calldata signature, bytes32 depositDataRoot) external payable {
        if (msg.sender != address(PUFFER_PROTOCOL)) {
            revert Unauthorized();
        }
        // EigenPod is deployed in this call
        EIGEN_POD_MANAGER.stake{ value: 32 ether }(pubKey, signature, depositDataRoot);
    }

    /**
     * @dev Claiming rewards from an EigenPod is a 2 step process.
     * We queue it by calling this function and then after a delay we claim it with `claimNonRestakingRewards`
     * Rewards get deposited to this PufferModule smart contract.
     * The guardians then generate the Rewards MerkleTree and the node operators claim their Beacon Chain rewards by `collectRewards`
     */
    function queueNonRestakingRewards() external {
        PufferModuleStorage storage $ = _getPufferProtocolStorage();
        uint256 lastClaimTimestamp = $.lastClaimTimestamp;
        // 864000 = 10 days in seconds
        if (block.timestamp - lastClaimTimestamp < 864000) {
            revert TooSoon();
        }
        $.lastClaimTimestamp = block.timestamp;
        $.eigenPod.withdrawBeforeRestaking();
    }

    function claimNonRestakingRewards() external {
        EIGEN_WITHDRAWAL_ROUTER.claimDelayedWithdrawals(address(this), type(uint256).max);
    }

    function collectRestakingRewards() external {
        //@todo
    }

    function getEigenPod() external view returns (address) {
        PufferModuleStorage storage $ = _getPufferProtocolStorage();
        return address($.eigenPod);
    }

    function call(address to, uint256 amount, bytes calldata data) external returns (bool success, bytes memory) {
        if (msg.sender != address(PUFFER_PROTOCOL.PUFFER_ORACLE())) {
            revert Unauthorized();
        }
        // slither-disable-next-line arbitrary-send-eth
        return to.call{ value: amount }(data);
    }

    /**
     * @notice Submit a valid MerkleProof all their validators' staking rewards will be sent to node operator
     * @dev Anybody can trigger a claim of the rewards for any node operator as long as the proofs submitted are valid
     *
     * @param node is a node operator's wallet address
     * @param blockNumbers is the array of block numbers for which the sender is claiming the rewards
     * @param amounts is the array of amounts to claim
     * @param merkleProofs is the array of Merkle proofs
     */
    function collectRewards(
        address node,
        uint256[] calldata blockNumbers,
        uint256[] calldata amounts,
        bytes32[][] calldata merkleProofs
    ) external {
        PufferModuleStorage storage $ = _getPufferProtocolStorage();

        // Anybody can submit a valid proof and the ETH will be sent to the node operator
        uint256 ethToSend = 0;

        for (uint256 i = 0; i < amounts.length; ++i) {
            if ($.claimedRewards[blockNumbers[i]][node]) {
                revert AlreadyClaimed(blockNumbers[i], node);
            }

            bytes32 rewardsRoot = $.rewardsRoots[blockNumbers[i]];
            bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(node, amounts[i]))));

            if (MerkleProof.verifyCalldata(merkleProofs[i], rewardsRoot, leaf)) {
                $.claimedRewards[blockNumbers[i]][node] = true;
                ethToSend += amounts[i];
            }
        }

        if (ethToSend == 0) {
            revert NothingToClaim(node);
        }

        payable(node).sendValue(ethToSend);
    }

    /**
     * @notice Posts the rewards root for this module
     * @param root is the Merkle Root hash
     * @param blockNumber is the block number for when the Merkle Proof was generated
     */
    function postRewardsRoot(bytes32 root, uint256 blockNumber, bytes[] calldata guardianSignatures) external {
        PufferModuleStorage storage $ = _getPufferProtocolStorage();

        if (blockNumber <= $.lastProofOfRewardsBlockNumber) {
            revert InvalidBlockNumber(blockNumber);
        }

        IGuardianModule guardianModule = PUFFER_PROTOCOL.GUARDIAN_MODULE();

        bytes32 signedMessageHash = LibGuardianMessages._getModuleRewardsRootMessage($.moduleName, root, blockNumber);

        bool validSignatures = guardianModule.validateGuardiansEOASignatures(guardianSignatures, signedMessageHash);
        if (!validSignatures) {
            revert Unauthorized();
        }

        $.lastProofOfRewardsBlockNumber = blockNumber;
        $.rewardsRoots[blockNumber] = root;
        emit RewardsRootPosted(blockNumber, root);
    }

    /**
     * @notice Returns the block number of when the latest rewards proof was posted
     */
    function getLastProofOfRewardsBlock() external view returns (uint256) {
        PufferModuleStorage storage $ = _getPufferProtocolStorage();
        return $.lastProofOfRewardsBlockNumber;
    }

    /**
     * @inheritdoc IPufferModule
     */
    function getWithdrawalCredentials() public view returns (bytes memory) {
        // Withdrawal credentials for EigenLayer modules are EigenPods
        PufferModuleStorage storage $ = _getPufferProtocolStorage();
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), $.eigenPod);
    }

    /**
     * @inheritdoc IPufferModule
     */
    function NAME() external view returns (bytes32) {
        PufferModuleStorage storage $ = _getPufferProtocolStorage();
        return $.moduleName;
    }

    // /**
    //  * @notice Registers this module as the operator in EigenLayer
    //  * @param metadataURI is a URI for the operator's metadata, i.e. a link providing more details on the operator.
    //  * @param delegationApprover Address to verify signatures when a staker wishes to delegate to the operator, as well as controlling "forced undelegations".
    //  */
    // function _registerAsOperator(string calldata metadataURI, address delegationApprover) internal {
    //     EIGEN_DELEGATION_MANAGER.registerAsOperator(
    //         IDelegationManager.OperatorDetails({
    //             earningsReceiver: address(this), // All of the rewards go to this contract
    //             delegationApprover: delegationApprover,
    //             stakerOptOutWindowBlocks: 1000 // 1000 blocks
    //          }),
    //         metadataURI
    //     );
    // }

    // //@todo unused at the moment
    // function _modifyOperatorDetails(address delegationApprover, uint32 stakerOptOutWindowBlocks) internal {
    //     EIGEN_DELEGATION_MANAGER.modifyOperatorDetails(
    //         IDelegationManager.OperatorDetails({
    //             stakerOptOutWindowBlocks: stakerOptOutWindowBlocks,
    //             delegationApprover: delegationApprover,
    //             earningsReceiver: address(this)
    //         })
    //     );
    // }

    function _getPufferProtocolStorage() internal pure returns (PufferModuleStorage storage $) {
        // solhint-disable-next-line
        assembly {
            $.slot := _PUFFER_MODULE_BASE_STORAGE
        }
    }
}
