// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferModule } from "puffer/interface/IPufferModule.sol";
import { IGuardianModule } from "puffer/interface/IGuardianModule.sol";
import { AccessManaged } from "openzeppelin/access/manager/AccessManaged.sol";
import { TokenRescuer } from "puffer/TokenRescuer.sol";
import { IBeaconDepositContract } from "puffer/interface/IBeaconDepositContract.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { MerkleProof } from "openzeppelin/utils/cryptography/MerkleProof.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";
import { Unauthorized } from "puffer/Errors.sol";
import { LibGuardianMessages } from "puffer/LibGuardianMessages.sol";

/**
 * @title NoRestakingModule
 * @author Puffer Finance
 * @notice NoRestakingModule
 * @custom:security-contact security@puffer.fi
 */
contract NoRestakingModule is IPufferModule, AccessManaged, TokenRescuer {
    using SafeTransferLib for address;

    /**
     * @notice Thrown if the deposit to beacon chain contract failed
     * @dev Signature "0x4f4a4e8e"
     */
    error FailedDeposit();

    /**
     * @notice Thrown if guardians try to post root for an invalid block number
     * @dev Signature "0x9f4aafbe"
     */
    error InvalidBlockNumber(uint256 blockNumber);

    /**
     * @notice Thrown if the rewards are already claimed for a `blockNumber`
     * @dev Signature "0xa9214540"
     */
    error AlreadyClaimed(uint256 blockNumber, address node);

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
     * @notice Beacon chain deposit contract
     */
    address public immutable BEACON_CHAIN_DEPOSIT_CONTRACT;

    /**
     * @notice Module Name
     */
    bytes32 public immutable NAME;

    /**
     * @notice Mapping of a blockNumber and the MerkleRoot for that rewards period
     */
    mapping(uint256 blockNumber => bytes32 root) public rewardsRoots;

    /**
     * @notice Mapping that stores which node operators have claimed the rewards for a certain blockNumber
     */
    mapping(uint256 blockNumber => mapping(address node => bool claimed)) public claimedRewards;

    /**
     * @dev The last block number for when the rewards root was posted
     */
    uint256 internal _lastProofOfRewardsBlockNumber;

    constructor(address initialAuthority, PufferProtocol puffer, address depositContract, bytes32 name)
        payable
        AccessManaged(initialAuthority)
        TokenRescuer(puffer)
    {
        NAME = name;
        BEACON_CHAIN_DEPOSIT_CONTRACT = depositContract;
    }

    /**
     * @notice Can Receive ETH donations
     */
    receive() external payable { }

    /**
     * @inheritdoc IPufferModule
     */
    function callStake(bytes calldata pubKey, bytes calldata signature, bytes32 depositDataRoot)
        external
        payable
        restricted
    {
        // slither-disable-next-line arbitrary-send-eth
        (bool success,) = BEACON_CHAIN_DEPOSIT_CONTRACT.call{ value: 32 ether }(
            abi.encodeCall(
                IBeaconDepositContract.deposit, (pubKey, getWithdrawalCredentials(), signature, depositDataRoot)
            )
        );
        if (!success) {
            revert FailedDeposit();
        }
    }

    /**
     * @notice Submit a valid MerkleProof and all their validators' staking rewards will be sent to node operator
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
    ) external restricted {
        // Anybody can submit a valid proof and the ETH will be sent to the node operator
        uint256 ethToSend = 0;

        for (uint256 i = 0; i < amounts.length; ++i) {
            if (claimedRewards[blockNumbers[i]][node]) {
                revert AlreadyClaimed(blockNumbers[i], node);
            }

            bytes32 rewardsRoot = rewardsRoots[blockNumbers[i]];
            bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(node, amounts[i]))));

            if (MerkleProof.verifyCalldata(merkleProofs[i], rewardsRoot, leaf)) {
                claimedRewards[blockNumbers[i]][node] = true;
                ethToSend += amounts[i];
            }
        }

        if (ethToSend == 0) {
            revert NothingToClaim(node);
        }

        node.safeTransferETH(ethToSend);
    }

    /**
     * @notice Posts the rewards root for this module
     * @dev Restricted to Guardians
     * @param root is the Merkle Root hash
     * @param blockNumber is the block number for when the Merkle Proof was generated
     */
    function postRewardsRoot(bytes32 root, uint256 blockNumber, bytes[] calldata guardianSignatures) external {
        if (blockNumber <= _lastProofOfRewardsBlockNumber) {
            revert InvalidBlockNumber(blockNumber);
        }

        IGuardianModule guardianModule = PUFFER_PROTOCOL.GUARDIAN_MODULE();

        bytes32 signedMessageHash = LibGuardianMessages._getModuleRewardsRootMessage(NAME, root, blockNumber);

        bool validSignatures = guardianModule.validateGuardiansEOASignatures(guardianSignatures, signedMessageHash);
        if (!validSignatures) {
            revert Unauthorized();
        }

        _lastProofOfRewardsBlockNumber = blockNumber;
        rewardsRoots[blockNumber] = root;
        emit RewardsRootPosted(blockNumber, root);
    }

    /**
     * @inheritdoc IPufferModule
     */
    function call(address to, uint256 amount, bytes calldata data)
        external
        restricted
        returns (bool success, bytes memory)
    {
        // slither-disable-next-line arbitrary-send-eth
        return to.call{ value: amount }(data);
    }

    /**
     * @notice Returns the block number of when the latest rewards proof was posted
     */
    function getLastProofOfRewardsBlock() external view returns (uint256) {
        return _lastProofOfRewardsBlockNumber;
    }

    /**
     * @inheritdoc IPufferModule
     */
    function getWithdrawalCredentials() public view returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(this));
    }
}
