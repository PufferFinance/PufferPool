// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { AccessManaged } from "openzeppelin/access/manager/AccessManaged.sol";
import { IPufferStrategy } from "puffer/interface/IPufferStrategy.sol";
import { PufferProtocol } from "puffer/PufferProtocol.sol";
import { AbstractVault } from "puffer/AbstractVault.sol";
import { IBeaconDepositContract } from "puffer/interface/IBeaconDepositContract.sol";
import { MerkleProof } from "openzeppelin/utils/cryptography/MerkleProof.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

/**
 * @title NoRestakingStrategy
 * @author Puffer Finance
 * @notice NoRestakingStrategy
 * @custom:security-contact security@puffer.fi
 */
contract NoRestakingStrategy is IPufferStrategy, AccessManaged, AbstractVault {
    using SafeTransferLib for address;

    /**
     * @notice Thrown if the deposit to beacon chain contract failed
     * @dev Signature "0x4f4a4e8e"
     */
    error FailedDeposit();

    /**
     * @notice Thrown if the rewards are already calimed for a `blockNumber`
     * @dev Signature "0x916ba7f3"
     */
    error AlreadyClaimed(uint256 blockNumber, bytes32 pubKeyHash);

    /**
     * @notice Emitted when the rewards MerkleRoot `root` for a `blockNumber` is posted
     */
    event RewardsRootPosted(uint256 indexed blockNumber, bytes32 root);

    /**
     * @notice Emitted when the full withdrawals MerkleRoot `root` for a `blockNumber` is posted
     */
    event FullWithdrawalsRootPosted(uint256 indexed blockNumber, bytes32 root);

    /**
     * @notice Beacon chain deposit contract
     */
    address public immutable BEACON_CHAIN_DEPOSIT_CONTRACT;

    /**
     * @notice Strategy Name
     */
    bytes32 public constant NAME = bytes32("NO_RESTAKING");

    /**
     * @notice Mapping of a blockNumber and the MerkleRoot for that rewards period
     */
    mapping(uint256 blockNumber => bytes32 root) public rewardsRoots;

    /**
     * @notice Mapping that stores which validators have claimed the rewards for a certain blockNumber
     */
    mapping(uint256 blockNumber => mapping(bytes32 pubKeyHash => bool claimed)) public claimedRewards;

    uint256 internal _lastProofOfRewardsBlockNumber;

    //@todo PART
    //@todo figure out if we want to have this in our PufferProtocol contract or per strategy?
    mapping(uint256 blockNumber => bytes32 root) public fullWithdrawalsRoots;

    error InvalidMerkleProof();

    error InvalidBlockNumber(uint256 blockNumber);

    constructor(address initialAuthority, PufferProtocol puffer, address depositContract)
        payable
        AccessManaged(initialAuthority)
        AbstractVault(puffer)
    {
        BEACON_CHAIN_DEPOSIT_CONTRACT = depositContract;
    }

    /**
     * @notice Can Receive ETH donations
     */
    receive() external payable { }

    /**
     * @inheritdoc IPufferStrategy
     */
    function callStake(bytes calldata pubKey, bytes calldata signature, bytes32 depositDataRoot)
        external
        payable
        restricted
    {
        (bool success,) = BEACON_CHAIN_DEPOSIT_CONTRACT.call(
            abi.encodeCall(
                IBeaconDepositContract.deposit, (pubKey, getWithdrawalCredentials(), signature, depositDataRoot)
            )
        );
        if (!success) {
            revert FailedDeposit();
        }
    }

    /**
     * @notice Submit a valid MerkleProof and the staking rewards will be sent to node operaator
     * @dev Anybody can claim the rewards for any validator as long as the proofs submitted are valid
     *
     * @param node is a node operator's wallet
     * @param pubKeyHash is a keccak256 hash of the validator's public key
     * @param blockNumbers is the array of block numbers for which the sender is claiming the rewards
     * @param amounts is the array of amounts to claim
     * @param wasSlashed is the array indicating if the validator was slashed in that period
     * @param merkleProofs is the array of Merkle proofs
     */
    function collectRewards(
        address node,
        bytes32 pubKeyHash,
        uint256[] calldata blockNumbers,
        uint256[] calldata amounts,
        bool[] calldata wasSlashed,
        bytes32[][] calldata merkleProofs
    ) external {
        // Anybody can submit a valid proof and the ETH will be sent to node
        uint256 ethToSend = 0;

        for (uint256 i = 0; i < amounts.length; ++i) {
            if (claimedRewards[blockNumbers[i]][pubKeyHash]) {
                revert AlreadyClaimed(blockNumbers[i], pubKeyHash);
            }

            bytes32 rewardsRoot = rewardsRoots[blockNumbers[i]];
            bytes32 leaf = keccak256(abi.encode(node, amounts[i], wasSlashed[i]));

            if (MerkleProof.verifyCalldata(merkleProofs[i], rewardsRoot, leaf)) {
                claimedRewards[blockNumbers[i]][pubKeyHash] = true;
                ethToSend += amounts[i];
            }
        }

        node.safeTransferETH(ethToSend);
    }

    /**
     * @notice Submit a valid MerkleProof and get back the Bond deposited if the validator was not slashed
     * @dev Anybody can trigger a validator exit as long as the proofs submitted are valid
     *
     */
    function stopValidator(
        bytes32 startegyName,
        uint256 validatorIndex,
        uint256 blockNumber,
        uint256 withdrawalAmount,
        bool wasSlashed,
        bytes32[] calldata merkleProof
    ) external {
        bytes32 leaf = keccak256(abi.encode(startegyName, validatorIndex, withdrawalAmount));

        bytes32 withdrawalRoot = fullWithdrawalsRoots[blockNumber];

        if (MerkleProof.verifyCalldata(merkleProof, withdrawalRoot, leaf)) {
            // Burn everything if the validator was slashed
            uint256 burnAmount = 0;

            if (wasSlashed) {
                burnAmount = 2 ether;
            }

            if (withdrawalAmount < 32 ether) {
                //@todo ?
                // Burn everything?
            }

            PUFFER_PROTOCOL.stopValidator(startegyName, validatorIndex, burnAmount);

            PUFFER_PROTOCOL.getPufferPool().depositETHWithoutMinting{ value: withdrawalAmount }();
        }

        revert InvalidMerkleProof();
    }

    /**
     * @notice Posts the rewards root for this strategy
     * @dev Restricted to Guardians
     * @param root is the Merkle Root hash
     * @param blockNumber is the block number for when the Merkle Proof was generated
     */
    function postFullWithdrawalsRoot(bytes32 root, uint256 blockNumber) external restricted {
        if (blockNumber <= _lastProofOfRewardsBlockNumber) {
            revert InvalidBlockNumber(blockNumber);
        }
        fullWithdrawalsRoots[blockNumber] = root;
        emit FullWithdrawalsRootPosted(blockNumber, root);
    }

    /**
     * @notice Posts the rewards root for this strategy
     * @dev Restricted to Guardians
     * @param root is the Merkle Root hash
     * @param blockNumber is the block number for when the Merkle Proof was generated
     */
    function postRewardsRoot(bytes32 root, uint256 blockNumber) external restricted {
        if (blockNumber <= _lastProofOfRewardsBlockNumber) {
            revert InvalidBlockNumber(blockNumber);
        }
        _lastProofOfRewardsBlockNumber = blockNumber;
        rewardsRoots[blockNumber] = root;
        emit RewardsRootPosted(blockNumber, root);
    }

    function getLastProofOfRewardsBlock() external view returns (uint256) {
        return _lastProofOfRewardsBlockNumber;
    }

    /**
     * @inheritdoc IPufferStrategy
     */
    function getWithdrawalCredentials() public view returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(this));
    }
}
