// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import { IPufferStrategy } from "puffer/interface/IPufferStrategy.sol";
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
 * @title NoRestakingStrategy
 * @author Puffer Finance
 * @notice NoRestakingStrategy
 * @custom:security-contact security@puffer.fi
 */
contract NoRestakingStrategy is IPufferStrategy, AccessManaged, TokenRescuer {
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
     * @notice Thrown if the rewards are already calimed for a `blockNumber`
     * @dev Signature "0x916ba7f3"
     */
    error AlreadyClaimed(uint256 blockNumber, bytes32 pubKeyHash);

    /**
     * @notice Thrown if the there is nothing to be claimed for the provided information
     * @dev Signature "0xb9eec102"
     */
    error NothingToClaim(bytes32 pubKeyHash);

    /**
     * @notice Emitted when the rewards MerkleRoot `root` for a `blockNumber` is posted
     */
    event RewardsRootPosted(uint256 indexed blockNumber, bytes32 root);

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

    /**
     * @dev The last block number for when the rewards root was posted
     */
    uint256 internal _lastProofOfRewardsBlockNumber;

    constructor(address initialAuthority, PufferProtocol puffer, address depositContract)
        payable
        AccessManaged(initialAuthority)
        TokenRescuer(puffer)
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
     * @notice Submit a valid MerkleProof and the staking rewards will be sent to node operator
     * @dev Anybody can trigger a claim of the rewards for any validator as long as the proofs submitted are valid
     *
     * @param node is a node operator's wallet
     * @param pubKeyHash is a keccak256 hash of the validator's public key
     * @param blockNumbers is the array of block numbers for which the sender is claiming the rewards
     * @param amounts is the array of amounts to claim
     * @param merkleProofs is the array of Merkle proofs
     */
    function collectRewards(
        address node,
        bytes32 pubKeyHash,
        uint256[] calldata blockNumbers,
        uint256[] calldata amounts,
        bytes32[][] calldata merkleProofs
    ) external restricted {
        // Anybody can submit a valid proof and the ETH will be sent to the node
        uint256 ethToSend = 0;

        for (uint256 i = 0; i < amounts.length; ++i) {
            if (claimedRewards[blockNumbers[i]][pubKeyHash]) {
                revert AlreadyClaimed(blockNumbers[i], pubKeyHash);
            }

            bytes32 rewardsRoot = rewardsRoots[blockNumbers[i]];
            bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(node, pubKeyHash, amounts[i]))));

            if (MerkleProof.verifyCalldata(merkleProofs[i], rewardsRoot, leaf)) {
                claimedRewards[blockNumbers[i]][pubKeyHash] = true;
                ethToSend += amounts[i];
            }
        }

        if (ethToSend == 0) {
            revert NothingToClaim(pubKeyHash);
        }

        node.safeTransferETH(ethToSend);
    }

    /**
     * @notice Posts the rewards root for this strategy
     * @dev Restricted to Guardians
     * @param root is the Merkle Root hash
     * @param blockNumber is the block number for when the Merkle Proof was generated
     */
    function postRewardsRoot(bytes32 root, uint256 blockNumber, bytes[] calldata guardianSignatures) external {
        if (blockNumber <= _lastProofOfRewardsBlockNumber) {
            revert InvalidBlockNumber(blockNumber);
        }

        IGuardianModule module = PUFFER_PROTOCOL.GUARDIAN_MODULE();

        bytes32 signedMessageHash =
            LibGuardianMessages.getNoRestakingStrategyRewardsRootMessage(NAME, root, blockNumber);

        bool validSignatures = module.validateGuardiansEOASignatures(guardianSignatures, signedMessageHash);
        if (!validSignatures) {
            revert Unauthorized();
        }

        _lastProofOfRewardsBlockNumber = blockNumber;
        rewardsRoots[blockNumber] = root;
        emit RewardsRootPosted(blockNumber, root);
    }

    /**
     * @inheritdoc IPufferStrategy
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
     * @inheritdoc IPufferStrategy
     */
    function getWithdrawalCredentials() public view returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(1)), bytes11(0), address(this));
    }
}
